"""Hosted Linux proof: patched Codex, TLS mock, private durable ledger, no egress."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from agentguard.evaluation.stage1_live_pricing import pricing_policy_digest
from agentguard.evaluation.stage1_metering import canonical_bytes, codex_metered_argv
from agentguard.evaluation.stage1_study_ledger import LedgerScope


ROOT = Path(__file__).parents[2]
BASE = (
    "gcr.io/distroless/python3-debian13:nonroot@"
    "sha256:ab7db4566f1d345612bcd57e1d33d8beb428d111f477dac98521a98fa4ab754d"
)
MODEL = "gpt-5.2-2025-12-11"
FAKE_AGENT = "AGENTGUARD_FAKE_AGENT_TOKEN_FOR_INTERNAL_GATEWAY"
FAKE_PROVIDER = "AGENTGUARD_FAKE_UPSTREAM_CREDENTIAL_CANARY"
SHA = "sha256:" + "a" * 64


def _docker(*args: str, check: bool = True, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(["docker", *args], capture_output=True, text=True,
                            check=False, timeout=timeout)
    if check and result.returncode:
        safe = (result.stdout + result.stderr).replace(FAKE_AGENT, "[REDACTED]")
        safe = safe.replace(FAKE_PROVIDER, "[REDACTED]")
        raise AssertionError(f"mock Docker operation failed: {safe[:1200]}")
    return result


def _certificate(directory: Path) -> tuple[Path, Path]:
    certificate = directory / "ca.pem"
    key = directory / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-days", "1", "-keyout", str(key), "-out", str(certificate),
        "-subj", "/CN=stage1-mock-provider",
        "-addext", "subjectAltName=DNS:stage1-mock-provider",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return certificate, key


def _ready(container: str, code: str, seconds: int = 20) -> None:
    deadline = time.monotonic() + seconds
    last_result: subprocess.CompletedProcess[str] | None = None
    while time.monotonic() < deadline:
        result = _docker("exec", container, "/usr/bin/python3", "-c", code,
                         check=False, timeout=5)
        if result.returncode == 0:
            return
        last_result = result
        time.sleep(0.2)
    state = _docker("inspect", "--format", "{{.State.Status}}/{{.State.ExitCode}}",
                    container, check=False)
    diagnostic = "unavailable"
    if last_result is not None:
        for name in ("SSLCertVerificationError", "SSLError", "ConnectionRefusedError",
                     "FileNotFoundError", "PermissionError", "URLError", "gaierror"):
            if name in last_result.stderr:
                diagnostic = name
                break
    if diagnostic == "unavailable":
        logs = _docker("logs", container, check=False)
        classes = re.findall(
            r"(?m)^(?:[A-Za-z_][A-Za-z_0-9]*\.)*([A-Za-z_][A-Za-z_0-9]*(?:Error|Exception)):",
            logs.stderr[-4096:],
        )
        if classes:
            diagnostic = classes[-1]
    status = state.stdout.strip() if state.returncode == 0 else "missing"
    raise AssertionError(
        f"local mock service did not become ready: state={status}, diagnostic={diagnostic}"
    )


@pytest.mark.docker
def test_patched_codex_uses_tls_mock_and_durable_b1_ledger(tmp_path: Path) -> None:
    candidate = os.environ.get("AGENTGUARD_B1_MODEL_IMAGE")
    if not candidate:
        pytest.skip("B1 patched candidate image is supplied by the hosted model-proof job")
    if _docker("info", "--format", "{{.ServerVersion}}", check=False).returncode:
        pytest.fail("hosted B1 Docker proof cannot skip when candidate image is supplied")
    for image in (BASE, candidate):
        assert _docker("image", "inspect", image, check=False).returncode == 0
    token = uuid.uuid4().hex[:12]
    network_agent = f"agentguard-b1-{token}-agent"
    network_provider = f"agentguard-b1-{token}-provider"
    volume = f"agentguard-b1-{token}-ledger"
    provider = f"agentguard-b1-{token}-mock"
    gateway = f"agentguard-b1-{token}-gateway"
    agent = f"agentguard-b1-{token}-codex"
    gateway_image = f"agentguard-b1-{token}-gateway:mock"
    provider_image = f"agentguard-b1-{token}-provider:mock"
    certificate, key = _certificate(tmp_path)
    config = tmp_path / "config.json"
    scope = LedgerScope(
        SHA, SHA, SHA, pricing_policy_digest(), SHA, "openai-api", MODEL,
        ("docker-mock-trial", "docker-contender-a", "docker-contender-b"),
        2, 2, 30, 20, 50, 120, "0.01", "0.02",
    )
    config.write_bytes(canonical_bytes({"scope": vars(scope), "output_cap": 8}))
    _docker("build", "--pull=false", "--network=none", "-f",
            "runtime-images/stage1-metering/Dockerfile.b1-mock", "-t", gateway_image,
            ".", timeout=240)
    _docker("build", "--pull=false", "--network=none", "-f",
            "runtime-images/stage1-metering/Dockerfile.mock", "-t", provider_image,
            ".", timeout=240)
    _docker("network", "create", "--internal", network_agent)
    _docker("network", "create", "--internal", network_provider)
    _docker("volume", "create", volume)
    try:
        _docker("run", "--rm", "--user", "0:0", "--network", "none", "--mount",
                f"type=volume,source={volume},target=/stage1-ledger", "--entrypoint",
                "/usr/bin/python3", gateway_image, "-c",
                "import os; os.chown('/stage1-ledger',65532,65532); os.chmod('/stage1-ledger',0o700)")
        _docker(
            "run", "-d", "--name", provider, "--network", network_provider,
            "--network-alias", "stage1-mock-provider", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--env", f"STAGE1_MOCK_MODEL={MODEL}", "--env", "STAGE1_MOCK_TLS=true",
            "--env", f"STAGE1_MOCK_TLS_FAKE_TOKEN={FAKE_PROVIDER}",
            "--env", "STAGE1_MOCK_CERT=/test/ca.pem", "--env", "STAGE1_MOCK_KEY=/test/key.pem",
            "--mount", f"type=bind,source={certificate},target=/test/ca.pem,readonly",
            "--mount", f"type=bind,source={key},target=/test/key.pem,readonly",
            provider_image,
        )
        _ready(provider,
               "import ssl,urllib.request; c=ssl.create_default_context(cafile='/test/ca.pem'); "
               "urllib.request.urlopen('https://stage1-mock-provider:8443/inspection',"
               "context=c,timeout=2).read()")
        _docker(
            "run", "-d", "--name", gateway, "--network", network_agent,
            "--network-alias", "stage1-metering-gateway", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "65532:65532", "--tmpfs",
            "/stage1-metering:rw,uid=65532,gid=65532,mode=0700,size=1m",
            "--mount", f"type=volume,source={volume},target=/stage1-ledger",
            "--mount", f"type=bind,source={config},target=/stage1-config/config.json,readonly",
            "--mount", f"type=bind,source={certificate},target=/stage1-config/ca.pem,readonly",
            "--env", "STAGE1_B1_MOCK_ONLY=true",
            "--env", f"STAGE1_B1_SYNTHETIC_TOKEN={FAKE_AGENT}",
            "--env", f"STAGE1_B1_FAKE_UPSTREAM_TOKEN={FAKE_PROVIDER}",
            gateway_image,
        )
        _docker("network", "connect", network_provider, gateway)
        _ready(gateway,
               "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz',"
               "timeout=2).read()")
        topology = json.loads(_docker("inspect", gateway).stdout)[0]["NetworkSettings"]["Networks"]
        assert set(topology) == {network_agent, network_provider}
        assert json.loads(_docker("network", "inspect", network_agent).stdout)[0]["Internal"] is True
        assert json.loads(_docker("network", "inspect", network_provider).stdout)[0]["Internal"] is True
        bypass = _docker("run", "--rm", "--network", network_agent, "--read-only",
                         "--entrypoint", "/usr/bin/python3", gateway_image, "-c",
                         "import socket; socket.create_connection(('stage1-mock-provider',8443),timeout=2)",
                         check=False)
        assert bypass.returncode != 0
        result = _docker(
            "run", "--name", agent, "--network", network_agent, "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "10001:10001", "--tmpfs", "/tmp:rw,uid=10001,gid=10001,size=16m",
            "--tmpfs", "/nonexistent:rw,uid=10001,gid=10001,size=16m",
            "--env", f"CODEX_API_KEY={FAKE_AGENT}", "--env", f"CODEX_MODEL={MODEL}",
            candidate, *codex_metered_argv(MODEL), timeout=120, check=False,
        )
        safe_output = (result.stdout + result.stderr).replace(FAKE_AGENT, "[REDACTED]")
        safe_output = safe_output.replace(FAKE_PROVIDER, "[REDACTED]")
        if result.returncode:
            state = _docker("exec", gateway, "/usr/bin/python3", "-c",
                            "import json; from pathlib import Path; p=Path('/stage1-metering/evidence.json'); "
                            "print(json.loads(p.read_text()).get('failure_reason','none') if p.exists() else 'missing')",
                            check=False)
            reason = state.stdout.strip()
            assert result.returncode == 0, (
                f"patched candidate failed; gateway_denial={reason if reason.isascii() and len(reason) < 100 else 'unavailable'}"
            )
        assert "mock complete" in safe_output
        evidence = _docker("exec", gateway, "/usr/bin/python3", "-c",
                           "from pathlib import Path; import sys; p=Path('/stage1-metering/evidence.json'); "
                           "b=p.read_bytes(); assert len(b)<65536; sys.stdout.buffer.write(b)").stdout
        assert json.loads(evidence)["events"]
        state = json.loads(_docker("exec", gateway, "/usr/bin/python3", "-c",
                                  "import json; print(open('/stage1-ledger/snapshot.json').read())").stdout)
        trial = state["trials"]["docker-mock-trial"]
        assert trial["pending"] is None
        assert trial["generations"] >= 1
        assert trial["counts"] == trial["generations"]
        for text in (evidence, json.dumps(state), _docker("logs", gateway).stdout,
                     _docker("logs", provider).stdout):
            assert FAKE_AGENT not in text and FAKE_PROVIDER not in text
        provider_inspection = _docker(
            "exec", provider, "/usr/bin/python3", "-c",
            "import ssl,urllib.request; c=ssl.create_default_context(cafile='/test/ca.pem'); "
            "print(urllib.request.urlopen('https://stage1-mock-provider:8443/inspection',"
            "context=c,timeout=3).read().decode())",
        ).stdout
        requests = json.loads(provider_inspection)["requests"]
        assert [entry["path"] for entry in requests] == [
            "/v1/responses/input_tokens", "/v1/responses",
        ]
        assert all(entry["reviewed_tool_contract"] for entry in requests)
        assert requests[-1]["model"] == MODEL
        assert requests[0]["keys"] == [
            "input", "instructions", "model", "parallel_tool_calls", "reasoning",
            "tool_choice", "tools",
        ]
        assert requests[-1]["keys"] == [
            "include", "input", "instructions", "max_output_tokens", "model",
            "parallel_tool_calls", "prompt_cache_key", "prompt_cache_retention",
            "reasoning", "store", "stream", "tool_choice", "tools",
        ]
        assert requests[-1]["prompt_cache_retention"] == "in_memory"
        assert requests[-1]["store"] is False
        assert requests[-1]["stream"] is True
        assert requests[-1]["reasoning_effort"] == "none"
        assert requests[-1]["reasoning_summary"] is None
        assert requests[-1]["verbosity"] is None
        contention = _docker("exec", gateway, "/usr/bin/python3", "-c", """
import json, multiprocessing, os
from pathlib import Path
from agentguard.evaluation.stage1_study_ledger import LedgerScope, StudyLedger
config = json.loads(Path('/stage1-config/config.json').read_text())
config['scope']['trial_ids'] = tuple(config['scope']['trial_ids'])
scope = LedgerScope(**config['scope'])
def compete(trial, barrier, queue):
    ledger = StudyLedger(Path('/stage1-ledger'), scope)
    barrier.wait(timeout=10)
    try:
        ledger.count(trial, 'count-' + trial)
        ledger.reserve(trial, 'generation-' + trial, 7, 8)
        queue.put('reserved')
    except Exception:
        queue.put('denied')
barrier = multiprocessing.Barrier(2)
queue = multiprocessing.Queue()
workers = [multiprocessing.Process(target=compete, args=(trial, barrier, queue))
           for trial in ('docker-contender-a', 'docker-contender-b')]
for worker in workers: worker.start()
for worker in workers:
    worker.join(timeout=15)
    assert worker.exitcode == 0
assert sorted([queue.get(timeout=2), queue.get(timeout=2)]) == ['denied', 'reserved']
print('concurrent-reservation-closed')
""")
        assert contention.stdout.strip() == "concurrent-reservation-closed"
        _docker("restart", gateway)
        _ready(gateway,
               "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz',"
               "timeout=2).read()")
        recovery = _docker("exec", gateway, "/usr/bin/python3", "-c", """
import json
from pathlib import Path
from agentguard.evaluation.stage1_study_ledger import LedgerScope, StudyLedger
from agentguard.evaluation.stage1_metering import MeteringError
config = json.loads(Path('/stage1-config/config.json').read_text())
config['scope']['trial_ids'] = tuple(config['scope']['trial_ids'])
ledger = StudyLedger(Path('/stage1-ledger'), LedgerScope(**config['scope']))
state = ledger.snapshot()['trials']
assert sum(item['pending'] is not None for item in state.values()) == 1
try:
    ledger.count('docker-mock-trial', 'after-restart')
except MeteringError:
    print('uncertain-reservation-retained')
else:
    raise AssertionError('restart released uncertain reservation')
""")
        assert recovery.stdout.strip() == "uncertain-reservation-retained"
    finally:
        _docker("rm", "-f", provider, gateway, agent, check=False)
        _docker("network", "rm", network_agent, network_provider, check=False)
        _docker("volume", "rm", volume, check=False)
        _docker("image", "rm", gateway_image, provider_image, check=False)
        for name in (provider, gateway, agent):
            assert _docker("inspect", name, check=False).returncode != 0
        for name in (network_agent, network_provider):
            assert _docker("network", "inspect", name, check=False).returncode != 0
        assert _docker("volume", "inspect", volume, check=False).returncode != 0
