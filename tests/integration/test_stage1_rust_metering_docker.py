"""Hosted-only mock proof for the compiled gateway; no public provider path."""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from agentguard.evaluation.stage1_live_pricing import pricing_policy_digest
from agentguard.evaluation.stage1_metering import canonical_bytes, codex_metered_argv
from agentguard.evaluation.stage1_study_ledger import LedgerScope


ROOT = Path(__file__).parents[2]
MODEL = "gpt-5.2-2025-12-11"
FAKE_AGENT = "AGENTGUARD_FAKE_RUST_AGENT_TOKEN_FOR_INTERNAL_GATEWAY"
FAKE_PROVIDER = "AGENTGUARD_FAKE_RUST_UPSTREAM_CREDENTIAL_CANARY"
BASE = (
    "gcr.io/distroless/python3-debian13:nonroot@"
    "sha256:ab7db4566f1d345612bcd57e1d33d8beb428d111f477dac98521a98fa4ab754d"
)


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
    certificate = tmp_path / "ca.pem"
    private_key = tmp_path / "key.pem"
    certificate_der = tmp_path / "ca.der"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-days", "1", "-keyout", str(private_key), "-out", str(certificate),
        "-subj", "/CN=stage1-mock-provider",
        "-addext", "subjectAltName=DNS:stage1-mock-provider",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([
        "openssl", "x509", "-in", str(certificate), "-outform", "DER", "-out", str(certificate_der),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sha = "sha256:" + "a" * 64
    scope = LedgerScope(
        sha, sha, sha, pricing_policy_digest(), sha, "openai-api", MODEL,
        ("docker-mock-trial", "docker-contender-a", "docker-contender-b"),
        2, 2, 30, 20, 50, 120, "0.01", "0.02",
    )
    configuration = tmp_path / "config.json"
    configuration.write_bytes(canonical_bytes({"scope": vars(scope), "output_cap": 8}))
    _docker("build", "--pull=false", "--network=none", "-f",
            "runtime-images/stage1-metering/Dockerfile.mock", "-t", provider_image, ".")
    _docker("network", "create", "--internal", agent_network)
    _docker("network", "create", "--internal", provider_network)
    _docker("volume", "create", ledger_volume)
    _docker("volume", "create", anchor_volume)
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
                provider_image)
        _docker("run", "-d", "--name", gateway, "--network", agent_network,
                "--network-alias", "stage1-metering-gateway", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--user", "65532:65532", "--tmpfs",
                "/stage1-metering:rw,uid=65532,gid=65532,mode=0700,size=1m",
                "--mount", f"type=volume,source={ledger_volume},target=/stage1-ledger",
                "--mount", f"type=volume,source={anchor_volume},target=/stage1-ledger-anchor",
                "--mount", f"type=bind,source={configuration},target=/stage1-config/config.json,readonly",
                "--mount", f"type=bind,source={certificate_der},target=/stage1-config/ca.der,readonly",
                "--env", "STAGE1_RUST_MOCK_ONLY=true",
                "--env", f"STAGE1_B1_SYNTHETIC_TOKEN={FAKE_AGENT}",
                "--env", f"STAGE1_B1_FAKE_UPSTREAM_TOKEN={FAKE_PROVIDER}",
                gateway_image)
        _docker("network", "connect", provider_network, gateway)
        _wait_ready(gateway)
        topology = json.loads(_docker("inspect", gateway).stdout)[0]
        assert topology["HostConfig"]["ReadonlyRootfs"] is True
        assert topology["Config"]["User"] == "65532:65532"
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
        assert result.returncode == 0, "patched Codex did not complete through compiled mock gateway"
        assert "mock complete" in result.stdout + result.stderr
        evidence_file = tmp_path / "evidence.json"
        _docker("cp", f"{gateway}:/stage1-metering/evidence.json", str(evidence_file))
        evidence = evidence_file.read_bytes()
        assert len(evidence) < 64 * 1024
        assert json.loads(evidence)["events"]
        ledger_file = tmp_path / "snapshot.json"
        _docker("cp", f"{gateway}:/stage1-ledger/snapshot.json", str(ledger_file))
        trial = json.loads(ledger_file.read_bytes())["trials"]["docker-mock-trial"]
        assert trial["pending"] is None
        assert trial["counts"] == trial["generations"] >= 1
        for value in (evidence.decode(), ledger_file.read_text(), result.stdout, result.stderr,
                      _docker("logs", gateway).stderr):
            assert FAKE_AGENT not in value and FAKE_PROVIDER not in value
        inspection = _docker(
            "exec", provider, "/usr/bin/python3", "-c",
            "import ssl,urllib.request; c=ssl.create_default_context(cafile='/test/ca.pem'); "
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
        print("RUST_METERING_MOCK_TLS_LEDGER_PASSED")
    finally:
        _docker("rm", "-f", gateway, provider, agent, check=False)
        _docker("network", "rm", agent_network, provider_network, check=False)
        _docker("volume", "rm", ledger_volume, check=False)
        _docker("volume", "rm", anchor_volume, check=False)
        _docker("image", "rm", provider_image, check=False)
        for name in (gateway, provider, agent):
            assert _docker("inspect", name, check=False).returncode != 0
