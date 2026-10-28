"""Hosted-only mock proof for the compiled gateway; no public provider path."""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentguard.evaluation.stage1_live_pricing import pricing_policy_digest
from agentguard.evaluation.stage1_metering import canonical_bytes, codex_metered_argv
from agentguard.evaluation.stage1_study_ledger import LedgerScope
from agentguard.evaluation.live_study_authorization import (
    LiveStudyAuthorization, canonical_live_study_authorization,
    live_study_authorization_digest, parse_live_study_authorization,
)
from agentguard.evaluation.runtime_images import (
    canonical_rootfs_digest, canonical_runtime_config, canonical_runtime_identity,
)
from agentguard.evaluation.stage1_credential_broker import (
    CredentialBrokerError, OneShotCredentialBroker, binding_for_rehearsal,
)
from agentguard.evaluation.stage1_rehearsal_projection import create_rehearsal_projection


ROOT = Path(__file__).parents[2]
MODEL = "gpt-5.2-2025-12-11"
FAKE_AGENT = "AGENTGUARD_FAKE_RUST_AGENT_TOKEN_FOR_INTERNAL_GATEWAY"
FAKE_PROVIDER = "AGENTGUARD_FAKE_RUST_UPSTREAM_CREDENTIAL_CANARY"
BASE = (
    "gcr.io/distroless/python3-debian13:nonroot@"
    "sha256:ab7db4566f1d345612bcd57e1d33d8beb428d111f477dac98521a98fa4ab754d"
)
AGENT_BASE = (
    "ghcr.io/richinmrudul/agentguard/stage1-codex-agent@"
    "sha256:31402671e20d26972f0345c4bf3263d4f5309c0f450cfbaece19b2b799caa93a"
)


def _candidate_agent_identity(image: str, tmp_path: Path) -> tuple[str, str]:
    inspected = json.loads(_docker("image", "inspect", image).stdout)
    container = _docker("create", image).stdout.strip()
    rootfs = tmp_path / "candidate-agent-rootfs.tar"
    try:
        _docker("export", "-o", str(rootfs), container)
    finally:
        _docker("rm", container, check=False)
    identity = canonical_runtime_identity(
        image_role="agent", base_image=AGENT_BASE,
        rootfs_digest=canonical_rootfs_digest(rootfs),
        runtime_config=canonical_runtime_config(inspected),
    )
    return inspected[0]["Id"], identity["identity"]


def _candidate_authorization(
    *, gateway_subject: str, agent_subject: str, now: datetime,
) -> LiveStudyAuthorization:
    def stamp(offset: int) -> str:
        return (now + timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%SZ")

    data = parse_live_study_authorization({
        "schema": "agentguard.live-study-authorization", "schema_version": 1,
        "authorization_id": "mock-only-candidate-rehearsal", "issuer": "hosted-test-only",
        "issued_at": stamp(-60), "not_before": stamp(-30), "expires_at": stamp(3600),
        "protocol_version": "v0.5-preregistered-contained-study",
        "credential_env_names": ["CODEX_API_KEY"],
        "destinations": [{"host": "api.openai.com", "port": 443}],
        "egress_policy_digest": "4" * 64,
        "evidence_bounds": {"max_output_bytes": 64000},
        "fixtures": [{"hash": "3" * 64, "id": "fixture-a", "task_id": "taskid-a"}],
        "images": {"agent": agent_subject, "gateway": gateway_subject},
        "limits": {"max_turns": 2, "per_trial_cost_usd": 1,
                   "per_trial_input_tokens": 30, "per_trial_output_tokens": 20,
                   "per_trial_timeout_seconds": 120, "total_cost_usd": 2,
                   "total_input_tokens": 30, "total_output_tokens": 20},
        "max_trial_count": 3, "plan_digest": "1" * 64,
        "profile": {"hash": "2" * 64, "id": "profile-a"},
        "provider": {"model_id": MODEL, "provider_id": "openai-api"},
        "publication_redaction_policy_digest": "5" * 64,
        "stop_thresholds": {"max_failures": 1},
        "trials": ["docker-mock-trial", "docker-contender-a", "docker-contender-b"],
    }, now=now)
    return LiveStudyAuthorization(data, live_study_authorization_digest(data))


def _contains_canary(path: Path, canary: bytes) -> bool:
    overlap = b""
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            if canary in overlap + chunk:
                return True
            overlap = chunk[-len(canary) + 1:]
    return False


def _docker(*args: str, check: bool = True, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["docker", *args], cwd=ROOT, text=True, capture_output=True,
        check=False, timeout=timeout,
    )
    if check and result.returncode:
        diagnostic = (result.stdout + result.stderr).replace(FAKE_AGENT, "[REDACTED]")
        diagnostic = diagnostic.replace(FAKE_PROVIDER, "[REDACTED]")
        raise AssertionError(f"mock Docker operation failed: {diagnostic[:1200]}")
    return result


def _wait_ready(container: str) -> None:
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        logs = _docker("logs", container, check=False)
        assert FAKE_AGENT not in logs.stdout + logs.stderr
        assert FAKE_PROVIDER not in logs.stdout + logs.stderr
        if "STAGE1_RUST_GATEWAY_READY" in logs.stderr:
            return
        state = _docker("inspect", "--format", "{{.State.Running}}", container, check=False)
        if state.stdout.strip() != "true":
            break
        time.sleep(0.2)
    raise AssertionError("compiled mock gateway did not become ready")


@pytest.mark.docker
def test_compiled_gateway_with_patched_codex_tls_and_ledger(tmp_path: Path) -> None:
    gateway_image = os.environ.get("AGENTGUARD_RUST_GATEWAY_IMAGE")
    agent_image = os.environ.get("AGENTGUARD_B1_MODEL_IMAGE")
    if not gateway_image or not agent_image:
        pytest.skip("hosted job supplies both candidate images")
    assert _docker("info", "--format", "{{.ServerVersion}}", check=False).returncode == 0
    for image in (gateway_image, agent_image, BASE):
        assert _docker("image", "inspect", image, check=False).returncode == 0

    marker = uuid.uuid4().hex[:12]
    agent_network = f"agentguard-rust-{marker}-agent"
    provider_network = f"agentguard-rust-{marker}-provider"
    ledger_volume = f"agentguard-rust-{marker}-ledger"
    anchor_volume = f"agentguard-rust-{marker}-anchor"
    provider = f"agentguard-rust-{marker}-mock"
    gateway = f"agentguard-rust-{marker}-gateway"
    agent = f"agentguard-rust-{marker}-codex"
    provider_image = f"agentguard-rust-{marker}-mock:local"
    root_certificate = tmp_path / "ca.pem"
    root_key = tmp_path / "ca-key.pem"
    certificate = tmp_path / "server.pem"
    private_key = tmp_path / "server-key.pem"
    certificate_request = tmp_path / "server.csr"
    certificate_der = tmp_path / "ca.der"
    evidence_dir = tmp_path / "gateway-evidence"
    evidence_dir.mkdir(mode=0o700)
    assert not list(evidence_dir.iterdir())
    evidence_started_at = time.time()
    subprocess.run([
        "sudo", "-n", "chown", "65532:65532", str(evidence_dir),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    directory_metadata = subprocess.run(
        ["sudo", "-n", "stat", "-c", "%u:%g:%a", str(evidence_dir)],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    assert directory_metadata == "65532:65532:700"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-days", "1", "-keyout", str(root_key), "-out", str(root_certificate),
        "-subj", "/CN=AgentGuard local mock CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([
        "openssl", "req", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-keyout", str(private_key), "-out", str(certificate_request),
        "-subj", "/CN=stage1-mock-provider",
        "-addext", "subjectAltName=DNS:stage1-mock-provider",
        "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "extendedKeyUsage=serverAuth",
        "-addext", "keyUsage=digitalSignature,keyEncipherment",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([
        "openssl", "x509", "-req", "-in", str(certificate_request),
        "-CA", str(root_certificate), "-CAkey", str(root_key), "-CAcreateserial",
        "-out", str(certificate), "-days", "1", "-sha256", "-copy_extensions", "copy",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([
        "openssl", "x509", "-in", str(root_certificate), "-outform", "DER",
        "-out", str(certificate_der),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    review = json.loads((ROOT / "dist/stage1-compiled-metering/compiled-gateway-review.json").read_text())
    gateway_subject = json.loads(_docker("image", "inspect", gateway_image).stdout)[0]["Id"]
    agent_subject, agent_identity = _candidate_agent_identity(agent_image, tmp_path)
    authorization = _candidate_authorization(
        gateway_subject=gateway_subject, agent_subject=agent_subject,
        now=datetime.now(timezone.utc),
    )
    sha = "sha256:"
    scope = LedgerScope(
        sha + authorization.digest, sha + "1" * 64, sha + "2" * 64,
        pricing_policy_digest(), sha + "5" * 64, "openai-api", MODEL,
        tuple(authorization.data["trials"]),
        2, 2, 30, 20, 50, 120, "0.01", "0.02",
    )
    projection = create_rehearsal_projection(
        authorization=authorization, scope=scope, trial_id="docker-mock-trial",
        nonce=secrets.token_hex(32),
        gateway_canonical_identity=review["candidate"]["identity"],
        gateway_binary_digest=review["candidate"]["rootfs"]["binary_digest"],
        agent_canonical_identity=agent_identity,
    )
    projection_file = tmp_path / "projection.json"
    projection_file.write_bytes(projection.canonical)
    authorization_file = tmp_path / "authorization.json"
    authorization_file.write_bytes(canonical_live_study_authorization(authorization.data).encode())
    broker = OneShotCredentialBroker(
        binding_for_rehearsal(projection), tmp_path, expected_peer_uid=65532,
        credential_source=lambda: FAKE_PROVIDER,
    )
    configuration = tmp_path / "config.json"
    configuration.write_bytes(canonical_bytes({
        "scope": vars(scope), "trial_id": "docker-mock-trial", "output_cap": 8,
    }))
    _docker("build", "--pull=false", "--network=none", "-f",
            "runtime-images/stage1-metering/Dockerfile.mock", "-t", provider_image, ".")
    _docker("network", "create", "--internal", agent_network)
    _docker("network", "create", "--internal", provider_network)
    _docker("volume", "create", ledger_volume)
    _docker("volume", "create", anchor_volume)
    broker_thread: threading.Thread | None = None
    broker_errors: list[str] = []
    try:
        _docker("run", "--rm", "--user", "0:0", "--network", "none",
                "--mount", f"type=volume,source={ledger_volume},target=/stage1-ledger",
                "--mount", f"type=volume,source={anchor_volume},target=/stage1-ledger-anchor",
                "--entrypoint", "/usr/bin/python3", BASE, "-c",
                "import os; "
                "[(os.chown(p,65532,65532),os.chmod(p,0o700)) "
                "for p in ('/stage1-ledger','/stage1-ledger-anchor')]")
        _docker("run", "-d", "--name", provider, "--network", provider_network,
                "--network-alias", "stage1-mock-provider", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--user", f"{os.getuid()}:{os.getgid()}",
                "--env", f"STAGE1_MOCK_MODEL={MODEL}", "--env", "STAGE1_MOCK_TLS=true",
                "--env", f"STAGE1_MOCK_TLS_FAKE_TOKEN={FAKE_PROVIDER}",
                "--env", "STAGE1_MOCK_CERT=/test/ca.pem", "--env", "STAGE1_MOCK_KEY=/test/key.pem",
                "--mount", f"type=bind,source={certificate},target=/test/ca.pem,readonly",
                "--mount", f"type=bind,source={private_key},target=/test/key.pem,readonly",
                "--mount", f"type=bind,source={root_certificate},target=/test/root.pem,readonly",
                provider_image)
        subprocess.run(["sudo", "-n", "chown", "65532:65532", str(broker.socket_path)],
                       check=True, capture_output=True)
        def serve_broker() -> None:
            try:
                broker.serve_once()
            except Exception as error:
                broker_errors.append(type(error).__name__)
        broker_thread = threading.Thread(target=serve_broker, daemon=True)
        broker_thread.start()
        _docker("run", "-d", "--name", gateway, "--network", agent_network,
                "--network-alias", "stage1-metering-gateway", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--user", "65532:65532",
                "--mount", f"type=bind,source={evidence_dir},target=/stage1-metering",
                "--mount", f"type=volume,source={ledger_volume},target=/stage1-ledger",
                "--mount", f"type=volume,source={anchor_volume},target=/stage1-ledger-anchor",
                "--mount", f"type=bind,source={configuration},target=/stage1-config/config.json,readonly",
                "--mount", f"type=bind,source={projection_file},target=/stage1-config/projection.json,readonly",
                "--mount", f"type=bind,source={broker.socket_path},target=/stage1-credential.sock",
                "--mount", f"type=bind,source={certificate_der},target=/stage1-config/ca.der,readonly",
                "--env", "STAGE1_RUST_REHEARSAL=true",
                "--env", f"STAGE1_B1_SYNTHETIC_TOKEN={FAKE_AGENT}",
                gateway_image)
        _docker("network", "connect", provider_network, gateway)
        _wait_ready(gateway)
        broker_thread.join(timeout=5)
        assert not broker_thread.is_alive() and not broker_errors
        assert not broker.socket_path.exists()
        assert not list(tmp_path.glob("agentguard-handoff-*"))
        with pytest.raises(CredentialBrokerError):
            broker.serve_once()
        topology = json.loads(_docker("inspect", gateway).stdout)[0]
        assert topology["HostConfig"]["ReadonlyRootfs"] is True
        assert topology["Config"]["User"] == "65532:65532"
        assert FAKE_PROVIDER not in json.dumps(topology)
        assert all("CODEX_API_KEY" not in value for value in topology["Config"]["Env"])
        assert any(mount["Destination"] == "/stage1-credential.sock" for mount in topology["Mounts"])
        assert set(topology["NetworkSettings"]["Networks"]) == {agent_network, provider_network}
        bypass = _docker(
            "run", "--rm", "--network", agent_network, "--read-only",
            "--entrypoint", "/usr/bin/python3", BASE, "-c",
            "import socket; socket.create_connection(('stage1-mock-provider',8443),timeout=2)",
            check=False,
        )
        assert bypass.returncode != 0
        result = _docker(
            "run", "--name", agent, "--network", agent_network, "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "10001:10001", "--tmpfs", "/tmp:rw,uid=10001,gid=10001,size=16m",
            "--tmpfs", "/nonexistent:rw,uid=10001,gid=10001,size=16m",
            "--env", f"CODEX_API_KEY={FAKE_AGENT}", "--env", f"CODEX_MODEL={MODEL}",
            agent_image, *codex_metered_argv(MODEL), check=False, timeout=120,
        )
        agent_topology = json.loads(_docker("inspect", agent).stdout)[0]
        assert FAKE_PROVIDER not in json.dumps(agent_topology)
        assert all(mount["Destination"] != "/stage1-credential.sock"
                   for mount in agent_topology["Mounts"])
        if result.returncode:
            gateway_logs = _docker("logs", gateway, check=False).stderr
            classes = sorted(set(re.findall(
                r"STAGE1_RUST_(?:DENIAL_[A-Z_]+|STAGE_[A-Z_]+|GATEWAY_READY|GATEWAY_STOPPED)", gateway_logs,
            )))[:16]
            state = _docker(
                "inspect", "--format", "{{.State.Running}}:{{.State.ExitCode}}",
                gateway, check=False,
            ).stdout.strip()
            provider_state = _docker(
                "inspect", "--format", "{{.State.Running}}:{{.State.ExitCode}}",
                provider, check=False,
            ).stdout.strip()
            diagnostic = {
                "schema": "agentguard.stage1-rust-mock-failure",
                "gateway_classes": classes,
                "gateway_state": state if re.fullmatch(r"(?:true|false):[0-9]{1,3}", state) else "unknown",
                "provider_state": (
                    provider_state if re.fullmatch(r"(?:true|false):[0-9]{1,3}", provider_state)
                    else "unknown"
                ),
                "agent_exit_code": result.returncode,
            }
            path = ROOT / "dist/stage1-compiled-metering/mock-failure.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(diagnostic, sort_keys=True) + "\n", encoding="utf-8")
            raise AssertionError(f"compiled mock gateway denied patched Codex: {diagnostic}")
        assert "mock complete" in result.stdout + result.stderr
        malformed = _docker(
            "run", "--rm", "--network", agent_network, "--read-only",
            "--entrypoint", "/usr/bin/python3", BASE, "-c",
            "import socket; s=socket.create_connection(('stage1-metering-gateway',8080),timeout=3); "
            "s.sendall(b'POST /v1/responses HTTP/1.1\\r\\nHost: stage1-metering-gateway:8080\\r\\n' "
            "b'Content-Type: application/json\\r\\nContent-Length: 2\\r\\n' "
            "b'Content-Length: 2\\r\\n\\r\\n{}'); "
            "print(s.recv(128).decode('ascii').split('\\r\\n',1)[0])",
        )
        assert malformed.stdout.strip() == "HTTP/1.1 400 Rejected"
        evidence_file = tmp_path / "evidence.json"
        gateway_evidence = evidence_dir / "evidence.json"
        evidence_read = subprocess.run(
            ["sudo", "-n", "head", "-c", "65537", str(gateway_evidence)],
            check=False, capture_output=True,
        )
        if evidence_read.returncode:
            gateway_logs = _docker("logs", gateway, check=False).stderr
            classes = sorted(set(re.findall(
                r"STAGE1_RUST_(?:DENIAL_[A-Z_]+|STAGE_[A-Z_]+|GATEWAY_READY|GATEWAY_STOPPED)",
                gateway_logs,
            )))[:16]
            gateway_state = _docker(
                "inspect", "--format", "{{.State.Running}}:{{.State.ExitCode}}",
                gateway, check=False,
            ).stdout.strip()
            inspection = _docker(
                "exec", provider, "/usr/bin/python3", "-c",
                "import ssl,urllib.request; c=ssl.create_default_context(cafile='/test/root.pem'); "
                "print(urllib.request.urlopen('https://stage1-mock-provider:8443/inspection',"
                "context=c,timeout=3).read().decode())",
                check=False,
            )
            requests = json.loads(inspection.stdout).get("requests", []) if inspection.returncode == 0 else []
            paths = [entry.get("path") for entry in requests[:4] if isinstance(entry, dict)]
            diagnostic = {
                "gateway_classes": classes,
                "gateway_state": (
                    gateway_state if re.fullmatch(r"(?:true|false):[0-9]{1,3}", gateway_state)
                    else "unknown"
                ),
                "mock_request_count": min(len(requests), 100),
                "mock_paths": [path for path in paths if path in (
                    "/v1/responses/input_tokens", "/v1/responses",
                )],
                "evidence_read_succeeded": False,
            }
            raise AssertionError(f"compiled mock evidence absent: {diagnostic}")
        evidence = evidence_read.stdout
        metadata = subprocess.run(
            ["sudo", "-n", "stat", "-c", "%u:%g:%a:%s:%Y", str(gateway_evidence)],
            check=True, capture_output=True, text=True,
        ).stdout.strip().split(":")
        assert metadata[:3] == ["65532", "65532", "600"]
        assert 0 < int(metadata[3]) == len(evidence) < 64 * 1024
        assert int(metadata[4]) >= int(evidence_started_at) - 1
        evidence_file.write_bytes(evidence)
        parsed_evidence = json.loads(evidence)
        assert parsed_evidence["trial_closed"] is True
        statuses = [event["status"] for event in parsed_evidence["events"]]
        assert statuses[-1] == "rejected"
        assert statuses[:-1] and set(statuses[:-1]) == {"settled"}
        ledger_file = tmp_path / "snapshot.json"
        assert _docker("inspect", "--format", "{{.State.Running}}", gateway).stdout.strip() == "true"
        ledger_read = _docker(
            "run", "--rm", "--network", "none", "--read-only", "--user", "65532:65532",
            "--mount", f"type=volume,source={ledger_volume},target=/stage1-ledger,readonly",
            "--entrypoint", "/usr/bin/python3", BASE, "-c",
            "import pathlib,sys; b=pathlib.Path('/stage1-ledger/snapshot.json').read_bytes(); "
            "assert 0<len(b)<65536; sys.stdout.buffer.write(b)",
        )
        ledger_file.write_text(ledger_read.stdout, encoding="utf-8")
        trial = json.loads(ledger_file.read_bytes())["trials"]["docker-mock-trial"]
        assert trial["pending"] is None
        assert trial["failed"] is True
        assert trial["counts"] == trial["generations"] >= 1
        for value in (evidence.decode(), ledger_file.read_text(), result.stdout, result.stderr,
                      _docker("logs", gateway).stderr, authorization_file.read_text(),
                      projection_file.read_text(), configuration.read_text(),
                      json.dumps(topology), json.dumps(agent_topology)):
            assert FAKE_PROVIDER not in value
        assert FAKE_AGENT not in evidence.decode() + ledger_file.read_text() + _docker("logs", gateway).stderr
        inspection = _docker(
            "exec", provider, "/usr/bin/python3", "-c",
            "import ssl,urllib.request; c=ssl.create_default_context(cafile='/test/root.pem'); "
            "print(urllib.request.urlopen('https://stage1-mock-provider:8443/inspection',"
            "context=c,timeout=3).read().decode())",
        )
        requests = json.loads(inspection.stdout)["requests"]
        assert [entry["path"] for entry in requests] == [
            "/v1/responses/input_tokens", "/v1/responses",
        ]
        assert all(entry["reviewed_tool_contract"] for entry in requests)
        assert all(entry["model"] == MODEL for entry in requests)
        assert json.loads(_docker("network", "inspect", agent_network).stdout)[0]["Internal"] is True
        assert json.loads(_docker("network", "inspect", provider_network).stdout)[0]["Internal"] is True
        for path in tmp_path.rglob("*"):
            if path.is_file():
                assert not _contains_canary(path, FAKE_PROVIDER.encode()), path.name
        assert FAKE_PROVIDER not in _docker("network", "inspect", agent_network).stdout
        assert FAKE_PROVIDER not in _docker("network", "inspect", provider_network).stdout
        print("RUST_METERING_SOCKET_PROJECTION_TLS_CANARY_PASSED")
    finally:
        if broker_thread is not None:
            broker_thread.join(timeout=2)
        _docker("rm", "-f", gateway, provider, agent, check=False)
        _docker("network", "rm", agent_network, provider_network, check=False)
        _docker("volume", "rm", ledger_volume, check=False)
        _docker("volume", "rm", anchor_volume, check=False)
        _docker("image", "rm", provider_image, check=False)
        subprocess.run([
            "sudo", "-n", "chown", "-R", f"{os.getuid()}:{os.getgid()}", str(evidence_dir),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for name in (gateway, provider, agent):
            assert _docker("inspect", name, check=False).returncode != 0
    assert gateway_evidence.read_bytes() == evidence
