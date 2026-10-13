#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path
from typing import Any

SHA256_DIGEST_LENGTH = 71
GATEWAY_UID = 65532
GATEWAY_GID = 65532
CANARY = "AGENTGUARD_STAGE1_PUBLICATION_CANARY_310"
APPROVED_HOST = "mock-approved.test"
DISALLOWED_HOST = "mock-disallowed.test"
METADATA_HOST = "169.254.169.254"
GATEWAY_ALIAS = "stage1-egress-gateway"
PROVIDER_ALIAS = APPROVED_HOST
GATEWAY_PORT = 8080
PROVIDER_PORT = 443
MAX_EVIDENCE_BYTES = 1024 * 1024


class IntegrationError(ValueError):
    def __init__(self, message: str, diagnostics: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics or {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gateway-ref", required=True)
    parser.add_argument("--agent-ref", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gateway-identity", required=True)
    parser.add_argument("--agent-identity", required=True)
    args = parser.parse_args(argv)
    try:
        result = run_integration(
            gateway_ref=args.gateway_ref,
            agent_ref=args.agent_ref,
            gateway_identity=args.gateway_identity,
            agent_identity=args.agent_identity,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (IntegrationError, OSError, subprocess.SubprocessError) as error:
        failure = {
            "schema": "agentguard.stage1-pulled-digest-mock-egress-integration",
            "schema_version": 1,
            "status": "failed",
            "failure": str(error),
        }
        if isinstance(error, IntegrationError) and error.diagnostics:
            failure["diagnostics"] = error.diagnostics
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(failure, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(str(error), file=sys.stderr)
        return 1
    return 0


def run_integration(
    *,
    gateway_ref: str,
    agent_ref: str,
    gateway_identity: str,
    agent_identity: str,
) -> dict[str, Any]:
    _require_digest_ref(gateway_ref, "gateway ref")
    _require_digest_ref(agent_ref, "agent ref")
    _require_digest(gateway_identity, "gateway canonical identity")
    _require_digest(agent_identity, "agent canonical identity")
    if shutil.which("docker") is None:
        raise IntegrationError("Docker is required for pulled-digest integration")
    token = hashlib.sha256(f"{gateway_ref}\n{agent_ref}".encode("utf-8")).hexdigest()[:12]
    internal_network = f"ag-stage1-{token}-internal"
    outbound_network = f"ag-stage1-{token}-outbound"
    gateway = f"ag-stage1-{token}-gateway"
    provider = f"ag-stage1-{token}-provider"
    client = f"ag-stage1-{token}-client"
    agent = f"ag-stage1-{token}-agent"
    crash = f"ag-stage1-{token}-crash"
    cleanup_targets = [
        ("container", client),
        ("container", agent),
        ("container", gateway),
        ("container", provider),
        ("container", crash),
        ("network", internal_network),
        ("network", outbound_network),
    ]
    with tempfile.TemporaryDirectory(prefix="agentguard-stage1-publication-") as temp:
        root = Path(temp)
        evidence = root / "evidence"
        evidence.mkdir()
        policy = evidence / "policy.json"
        gateway_evidence = evidence / "gateway-evidence.json"
        client_script = root / "client.py"
        provider_script = root / "provider.py"
        policy.write_text(
            json.dumps(
                {
                    "destinations": [{"host": APPROVED_HOST, "port": PROVIDER_PORT}],
                    "schema": "agentguard.stage1-publication-local-egress-policy",
                    "schema_version": 1,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        provider_script.write_text(_provider_script(), encoding="utf-8")
        client_script.write_text(_client_script(), encoding="utf-8")
        steps: dict[str, Any] = {}
        diagnostics: dict[str, Any] = {}
        pending_failure = False
        try:
            _prepare_gateway_evidence_directory(evidence, gateway_ref, steps)
            _run(["docker", "network", "create", "--driver", "bridge", "--internal", internal_network], steps, "create_internal_network")
            _run(
                [
                    "docker",
                    "network",
                    "create",
                    "--driver",
                    "bridge",
                    "--internal",
                    "--subnet",
                    "198.51.100.0/24",
                    outbound_network,
                ],
                steps,
                "create_outbound_network",
            )
            _run(
                [
                    "docker",
                    "create",
                    "--name",
                    provider,
                    "--network",
                    outbound_network,
                    "--network-alias",
                    PROVIDER_ALIAS,
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,size=4m",
                    "--entrypoint",
                    "/usr/bin/python3",
                    "-v",
                    f"{provider_script}:/provider.py:ro",
                    gateway_ref,
                    "/provider.py",
                ],
                steps,
                "create_provider",
            )
            _run(
                [
                    "docker",
                    "create",
                    "--name",
                    gateway,
                    "--network",
                    internal_network,
                    "--network-alias",
                    GATEWAY_ALIAS,
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,size=4m",
                    "-v",
                    f"{evidence}:/agentguard-egress:rw",
                    gateway_ref,
                    "--policy",
                    "/agentguard-egress/policy.json",
                    "--evidence",
                    "/agentguard-egress/gateway-evidence.json",
                    "--host",
                    "0.0.0.0",
                    "--port",
                    str(GATEWAY_PORT),
                ],
                steps,
                "create_gateway",
            )
            _run(["docker", "network", "connect", outbound_network, gateway], steps, "connect_gateway_outbound")
            _run(["docker", "start", provider], steps, "start_provider")
            _run(["docker", "start", gateway], steps, "start_gateway")
            _assert_running(gateway, steps, "gateway_liveness")
            _assert_image_user(gateway_ref, "65532:65532", steps, "gateway_non_root")
            _assert_image_user(agent_ref, "10001:10001", steps, "agent_non_root")
            test_started_at = time.time()
            client_output = _run(
                [
                    "docker",
                    "run",
                    "--name",
                    client,
                    "--network",
                    internal_network,
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,size=4m",
                    "--entrypoint",
                    "/usr/bin/python3",
                    "-v",
                    f"{client_script}:/client.py:ro",
                    gateway_ref,
                    "/client.py",
                    GATEWAY_ALIAS,
                    str(GATEWAY_PORT),
                    APPROVED_HOST,
                    DISALLOWED_HOST,
                    METADATA_HOST,
                    str(PROVIDER_PORT),
                ],
                steps,
                "run_client_checks",
            )
            _run(["docker", "kill", "--signal", "INT", gateway], steps, "stop_gateway_for_evidence")
            _run(["docker", "wait", gateway], steps, "wait_gateway_for_evidence", check=False)
            agent_output = _run(
                [
                    "docker",
                    "run",
                    "--name",
                    agent,
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,size=4m",
                    "-e",
                    f"CODEX_API_KEY={CANARY}",
                    "-e",
                    "CODEX_MODEL=mock-local-only",
                    agent_ref,
                    "--version",
                ],
                steps,
                "run_agent_digest_smoke",
            )
            crash_output = _run(
                [
                    "docker",
                    "run",
                    "--name",
                    crash,
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    gateway_ref,
                    "--policy",
                    "/missing-policy.json",
                    "--evidence",
                    "/tmp/missing-evidence.json",
                ],
                steps,
                "run_gateway_crash_probe",
                check=False,
            )
            if crash_output.returncode == 0:
                raise IntegrationError("gateway crash probe unexpectedly succeeded")
            diagnostics = _safe_failure_diagnostics(
                evidence_dir=evidence,
                expected_file=gateway_evidence,
                gateway_container=gateway,
            )
            gateway_payload = _load_gateway_evidence(
                gateway_evidence,
                test_started_at=test_started_at,
                diagnostics=diagnostics,
            )
            client_payload = _json_from_stdout(client_output.stdout, "client checks")
            _validate_client_payload(client_payload)
            if "codex-cli 0.159.2" not in agent_output.stdout:
                raise IntegrationError("agent digest smoke did not report reviewed Codex version")
            serialized = json.dumps(
                {
                    "steps": steps,
                    "client": client_payload,
                    "gateway": gateway_payload,
                    "agent_stdout": agent_output.stdout,
                    "agent_stderr": agent_output.stderr,
                    "crash_stdout": crash_output.stdout,
                    "crash_stderr": crash_output.stderr,
                },
                sort_keys=True,
            )
            if CANARY in serialized:
                raise IntegrationError("credential canary leaked into retained integration evidence")
            if "api.openai.com" in serialized or "openai.com" in serialized:
                raise IntegrationError("public provider hostname appeared in integration evidence")
            return {
                "schema": "agentguard.stage1-pulled-digest-mock-egress-integration",
                "schema_version": 1,
                "status": "passed",
                "local_only": True,
                "public_provider_contact": False,
                "public_internet_required": False,
                "gateway_ref": gateway_ref,
                "agent_ref": agent_ref,
                "gateway_canonical_identity": gateway_identity,
                "agent_canonical_identity": agent_identity,
                "checks": {
                    "digest_refs": True,
                    "non_root": True,
                    "read_only_root": True,
                    "bounded_tmpfs_and_evidence": True,
                    "approved_local_mock_destination": True,
                    "disallowed_destination_denied": True,
                    "direct_bypass_denied": True,
                    "metadata_destination_denied": True,
                    "credential_canary_not_retained": True,
                    "gateway_evidence_bounded_and_sanitized": True,
                    "gateway_crash_detected": True,
                    "cleanup_and_liveness": True,
                    "no_public_provider_contact": True,
                },
                "client": client_payload,
                "gateway_evidence": _gateway_evidence_file_summary(gateway_evidence),
                "gateway_event_count": len(gateway_payload.get("events", [])),
                "evidence_digest": "sha256:" + hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
            }
        except IntegrationError as error:
            pending_failure = True
            if not error.diagnostics:
                error.diagnostics.update(
                    _safe_failure_diagnostics(
                        evidence_dir=evidence,
                        expected_file=gateway_evidence,
                        gateway_container=gateway,
                    )
                )
            raise
        except BaseException:
            pending_failure = True
            raise
        finally:
            cleanup = _cleanup(cleanup_targets)
            restored = _restore_gateway_evidence_directory(evidence, gateway_ref, steps)
            if cleanup["overall_complete"] is not True and not pending_failure:
                raise IntegrationError("pulled-digest integration cleanup incomplete")
            if restored["complete"] is not True and not pending_failure:
                raise IntegrationError("gateway evidence directory cleanup restoration failed")


def _run(
    argv: list[str],
    steps: dict[str, Any],
    label: str,
    *,
    check: bool = True,
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=timeout)
    steps[label] = _step_evidence(result)
    if check and result.returncode != 0:
        raise IntegrationError(f"{label} failed: {result.stderr[:500]}")
    return result


def _assert_running(container: str, steps: dict[str, Any], label: str) -> None:
    result = _run(
        ["docker", "container", "inspect", "--format", "{{json .State}}", container],
        steps,
        label,
    )
    state = _json_from_stdout(result.stdout, label)
    if state.get("Running") is not True:
        raise IntegrationError("gateway liveness verification failed")


def _assert_image_user(image: str, expected: str, steps: dict[str, Any], label: str) -> None:
    result = _run(
        ["docker", "image", "inspect", "--format", "{{.Config.User}}", image],
        steps,
        label,
    )
    if result.stdout.strip() != expected:
        raise IntegrationError(f"{label} mismatch")


def _prepare_gateway_evidence_directory(
    evidence: Path,
    gateway_ref: str,
    steps: dict[str, Any],
) -> None:
    command = (
        "import json, os, stat; "
        "path='/agentguard-egress'; "
        f"os.chown(path, {GATEWAY_UID}, {GATEWAY_GID}); "
        "os.chmod(path, 0o755); "
        "st=os.stat(path); "
        "print(json.dumps({'uid': st.st_uid, 'gid': st.st_gid, 'mode': oct(stat.S_IMODE(st.st_mode))}, sort_keys=True))"
    )
    result = _run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CHOWN",
            "--cap-add",
            "FOWNER",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "0:0",
            "--entrypoint",
            "/usr/bin/python3",
            "-v",
            f"{evidence}:/agentguard-egress:rw",
            gateway_ref,
            "-c",
            command,
        ],
        steps,
        "prepare_gateway_evidence_directory",
    )
    payload = _json_from_stdout(result.stdout, "prepare gateway evidence directory")
    if payload.get("uid") != GATEWAY_UID or payload.get("gid") != GATEWAY_GID:
        raise IntegrationError("gateway evidence directory ownership mismatch")
    if payload.get("mode") != "0o755":
        raise IntegrationError("gateway evidence directory mode mismatch")


def _restore_gateway_evidence_directory(
    evidence: Path,
    gateway_ref: str,
    steps: dict[str, Any],
) -> dict[str, Any]:
    if not evidence.exists():
        return {"complete": True, "reason": "missing"}
    command = (
        "import json, os, pathlib, stat; "
        "path=pathlib.Path('/agentguard-egress'); "
        f"uid={os.getuid()}; gid={os.getgid()}; "
        "os.chown(path, uid, gid); os.chmod(path, 0o755); "
        "\nfor item in path.rglob('*'):\n"
        "    os.chown(item, uid, gid)\n"
        "    mode = 0o755 if item.is_dir() else 0o644\n"
        "    os.chmod(item, mode)\n"
        "st=os.stat(path); "
        "print(json.dumps({'uid': st.st_uid, 'gid': st.st_gid, 'mode': oct(stat.S_IMODE(st.st_mode))}, sort_keys=True))"
    )
    result = _run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CHOWN",
            "--cap-add",
            "FOWNER",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "0:0",
            "--entrypoint",
            "/usr/bin/python3",
            "-v",
            f"{evidence}:/agentguard-egress:rw",
            gateway_ref,
            "-c",
            command,
        ],
        steps,
        "restore_gateway_evidence_directory",
        check=False,
    )
    complete = result.returncode == 0
    if complete:
        payload = _json_from_stdout(result.stdout, "restore gateway evidence directory")
        complete = (
            payload.get("uid") == os.getuid()
            and payload.get("gid") == os.getgid()
            and payload.get("mode") == "0o755"
        )
    return {"complete": complete, "returncode": result.returncode}


def _cleanup(targets: list[tuple[str, str]]) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    complete = True
    for kind, name in targets:
        command = ["docker", "rm", "-f", name] if kind == "container" else ["docker", "network", "rm", name]
        result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)
        removed = result.returncode == 0 or "No such" in result.stderr or "not found" in result.stderr
        evidence[name] = "removed" if removed else "incomplete"
        complete = complete and removed
    evidence["overall_complete"] = complete
    return evidence


def _load_gateway_evidence(
    path: Path,
    *,
    test_started_at: float,
    diagnostics: dict[str, Any],
) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise IntegrationError("gateway evidence file missing", diagnostics)
    info = path.stat()
    if info.st_size <= 0 or info.st_size > MAX_EVIDENCE_BYTES:
        raise IntegrationError("gateway evidence size is out of bounds", diagnostics)
    if info.st_uid != GATEWAY_UID or info.st_gid != GATEWAY_GID:
        raise IntegrationError("gateway evidence ownership mismatch", diagnostics)
    if info.st_mtime < test_started_at:
        raise IntegrationError("gateway evidence is stale", diagnostics)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise IntegrationError("gateway evidence must be an object", diagnostics)
    status = data.get("gateway_status")
    events = data.get("events")
    if not isinstance(status, dict) or status.get("evidence_complete") is not True:
        raise IntegrationError("gateway evidence is incomplete", diagnostics)
    if not isinstance(events, list) or len(events) < 3:
        raise IntegrationError("gateway evidence did not record required decisions", diagnostics)
    _require_gateway_decisions(events, diagnostics)
    serialized = json.dumps(data, sort_keys=True)
    if CANARY in serialized:
        raise IntegrationError("credential canary leaked into gateway evidence", diagnostics)
    if "/tmp/" in serialized or "/Users/" in serialized or "/home/runner/" in serialized:
        raise IntegrationError("private host path leaked into gateway evidence", diagnostics)
    return data


def _require_gateway_decisions(events: list[object], diagnostics: dict[str, Any]) -> None:
    decisions: set[tuple[str, str, str]] = set()
    for item in events:
        if not isinstance(item, dict):
            raise IntegrationError("gateway evidence event must be an object", diagnostics)
        requested = item.get("requested")
        if not isinstance(requested, dict):
            raise IntegrationError("gateway evidence event missing requested destination", diagnostics)
        decisions.add(
            (
                str(requested.get("host", "")),
                str(item.get("decision", "")),
                str(item.get("reason", "")),
            )
        )
    expected = {
        (APPROVED_HOST, "allow", "approved_destination"),
        (DISALLOWED_HOST, "deny", "destination_not_approved"),
        (METADATA_HOST, "deny", "unsafe_destination"),
    }
    if not expected.issubset(decisions):
        raise IntegrationError("gateway evidence did not record required decisions", diagnostics)


def _gateway_evidence_file_summary(path: Path) -> dict[str, Any]:
    info = path.stat()
    return {
        "path": path.name,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": oct(info.st_mode & 0o777),
        "size": info.st_size,
        "digest": "sha256:" + _sha256_file(path),
    }


def _safe_failure_diagnostics(
    *,
    evidence_dir: Path,
    expected_file: Path,
    gateway_container: str,
) -> dict[str, Any]:
    diagnostics: dict[str, Any] = {
        "evidence_directory": _path_summary(evidence_dir),
        "expected_evidence_file": expected_file.name,
        "expected_evidence_file_state": _path_summary(expected_file),
        "evidence_directory_entries": _directory_entries(evidence_dir),
    }
    state = subprocess.run(
        ["docker", "container", "inspect", "--format", "{{json .State}}", gateway_container],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    diagnostics["gateway_container_state"] = _bounded_json_or_digest(state.stdout)
    diagnostics["gateway_container_state_returncode"] = state.returncode
    logs = subprocess.run(
        ["docker", "logs", "--tail", "40", gateway_container],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    diagnostics["gateway_log_stdout_digest"] = "sha256:" + hashlib.sha256(
        logs.stdout.encode("utf-8")
    ).hexdigest()
    diagnostics["gateway_log_stderr_digest"] = "sha256:" + hashlib.sha256(
        logs.stderr.encode("utf-8")
    ).hexdigest()
    diagnostics["gateway_log_returncode"] = logs.returncode
    return diagnostics


def _path_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"exists": False}
    info = path.lstat()
    return {
        "exists": True,
        "is_dir": path.is_dir(),
        "is_file": path.is_file(),
        "is_symlink": path.is_symlink(),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": oct(info.st_mode & 0o777),
        "size": info.st_size,
    }


def _directory_entries(path: Path) -> list[dict[str, Any]]:
    if not path.is_dir():
        return []
    entries: list[dict[str, Any]] = []
    for item in sorted(path.iterdir(), key=lambda candidate: candidate.name)[:16]:
        summary = _path_summary(item)
        summary["name"] = item.name
        entries.append(summary)
    return entries


def _bounded_json_or_digest(value: str) -> object:
    try:
        data = json.loads(value.strip())
    except json.JSONDecodeError:
        return {
            "digest": "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest(),
            "bytes": len(value.encode("utf-8")),
        }
    if not isinstance(data, dict):
        return {
            "digest": "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest(),
            "bytes": len(value.encode("utf-8")),
        }
    return {
        key: data.get(key)
        for key in ("Status", "Running", "ExitCode", "Error", "StartedAt", "FinishedAt")
    }


def _validate_client_payload(data: dict[str, Any]) -> None:
    expected = {
        "approved_status": 200,
        "disallowed_status": 403,
        "metadata_status": 403,
        "direct_bypass": "blocked",
    }
    for key, value in expected.items():
        if data.get(key) != value:
            raise IntegrationError(f"client mock-egress check failed for {key}")


def _json_from_stdout(stdout: str, label: str) -> dict[str, Any]:
    try:
        data = json.loads(stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as error:
        raise IntegrationError(f"{label} did not emit JSON") from error
    if not isinstance(data, dict):
        raise IntegrationError(f"{label} JSON must be an object")
    return data


def _step_evidence(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    return {
        "returncode": result.returncode,
        "stdout_digest": "sha256:" + hashlib.sha256(result.stdout.encode("utf-8")).hexdigest(),
        "stderr_digest": "sha256:" + hashlib.sha256(result.stderr.encode("utf-8")).hexdigest(),
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _provider_script() -> str:
    return textwrap.dedent(
        f"""
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
            def log_message(self, format, *args):
                return

        HTTPServer(("0.0.0.0", {PROVIDER_PORT}), Handler).serve_forever()
        """
    )


def _client_script() -> str:
    return r'''
import json
import socket
import sys

gateway_host, gateway_port, approved, disallowed, metadata, provider_port = sys.argv[1:7]
gateway_port = int(gateway_port)
provider_port = int(provider_port)

def proxy_request(host):
    sock = socket.create_connection((gateway_host, gateway_port), timeout=10)
    request = f"GET http://{host}:{provider_port}/ HTTP/1.1\r\nHost: {host}:{provider_port}\r\nConnection: close\r\n\r\n"
    sock.sendall(request.encode("ascii"))
    payload = b""
    while True:
        data = sock.recv(4096)
        if not data:
            break
        payload += data
    sock.close()
    first = payload.splitlines()[0].decode("ascii", "replace")
    return int(first.split()[1])

direct = "blocked"
try:
    socket.create_connection((approved, provider_port), timeout=3).close()
    direct = "connected"
except OSError:
    pass

print(json.dumps({
    "approved_status": proxy_request(approved),
    "disallowed_status": proxy_request(disallowed),
    "metadata_status": proxy_request(metadata),
    "direct_bypass": direct,
}, sort_keys=True))
'''


def _require_digest_ref(value: str, label: str) -> None:
    if "@" not in value:
        raise IntegrationError(f"{label} must use an immutable digest reference")
    digest = value.rsplit("@", 1)[1]
    _require_digest(digest, label)


def _require_digest(value: str, label: str) -> None:
    if len(value) != SHA256_DIGEST_LENGTH or not value.startswith("sha256:"):
        raise IntegrationError(f"{label} must be a sha256 digest")
    if any(character not in "0123456789abcdef" for character in value.removeprefix("sha256:")):
        raise IntegrationError(f"{label} must be a sha256 digest")


if __name__ == "__main__":
    raise SystemExit(main())
