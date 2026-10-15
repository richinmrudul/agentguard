"""Linux Docker proof using only pinned read-only images and internal mock networks."""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from agentguard.evaluation.stage1_metering import (
    MeteringLimits,
    MeteringScope,
    PricingPolicy,
    canonical_bytes,
    codex_metered_argv,
)


ROOT = Path(__file__).parents[2]
BASE = (
    "gcr.io/distroless/python3-debian13:nonroot@"
    "sha256:ab7db4566f1d345612bcd57e1d33d8beb428d111f477dac98521a98fa4ab754d"
)
PUBLISHED_AGENT = (
    "ghcr.io/richinmrudul/agentguard/stage1-codex-agent@"
    "sha256:31402671e20d26972f0345c4bf3263d4f5309c0f450cfbaece19b2b799caa93a"
)
AGENT = os.environ.get("AGENTGUARD_MODEL_COMPAT_IMAGE", PUBLISHED_AGENT)
MODEL = os.environ.get("AGENTGUARD_MODEL_COMPAT_MODEL", "stage1-mock-2026-10-14")
CANARY = "AGENTGUARD_FAKE_CREDENTIAL_CANARY"
SHA = "sha256:" + "a" * 64


def _docker(*args: str, timeout: int = 60, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False
    )
    if check and result.returncode:
        output = (result.stdout + result.stderr).replace(CANARY, "[REDACTED]")
        raise AssertionError(f"Docker operation failed: {output[:2000]}")
    return result


def _ready(container: str, seconds: int = 15) -> None:
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        state = _docker("inspect", "-f", "{{.State.Running}}", container)
        if state.stdout.strip() == "true":
            return
        time.sleep(0.2)
    raise AssertionError("mock container did not become live")


def _read_bounded_evidence(container: str) -> str | None:
    result = _docker(
        "exec", container, "/usr/bin/python3", "-c",
        "from pathlib import Path; import sys; p=Path('/stage1-metering/evidence.json'); "
        "b=p.read_bytes(); assert len(b)<=65536; sys.stdout.buffer.write(b)",
        check=False,
    )
    if result.returncode:
        return None
    assert len(result.stdout) <= 65536
    return result.stdout


@pytest.mark.docker
def test_frozen_codex_uses_only_internal_metered_mock_and_cleans_up(tmp_path: Path) -> None:
    probe = _docker("info", "--format", "{{.ServerVersion}}", check=False)
    if probe.returncode:
        if os.environ.get("AGENTGUARD_REQUIRE_DOCKER") == "1":
            pytest.fail("hosted Linux Docker proof cannot skip")
        pytest.skip("Docker daemon unavailable")
    for image in (BASE, AGENT):
        assert _docker("image", "inspect", image, check=False).returncode == 0, (
            "pinned test image must be preloaded before mock-only test"
        )

    token = uuid.uuid4().hex[:12]
    internal = f"agentguard-meter-{token}-internal"
    outbound = f"agentguard-meter-{token}-mock"
    provider = f"agentguard-meter-{token}-provider"
    gateway = f"agentguard-meter-{token}-gateway"
    agent = f"agentguard-meter-{token}-agent"
    gateway_image = f"agentguard-stage1-meter-{token}:test"
    provider_image = f"agentguard-stage1-mock-{token}:test"
    pricing = PricingPolicy(MODEL, "2026-10-14", "2026-10-14", "2.00", "0.50", "8.00")
    limits = MeteringLimits(2, 2, 20, 20, 40, 8, 60, "0.01", "0.02")
    scope = MeteringScope("docker-mock-trial", SHA, SHA, MODEL, pricing.canonical_digest)
    config = tmp_path / "config.json"
    config.write_bytes(canonical_bytes({
        "pricing": pricing.__dict__, "limits": limits.__dict__, "scope": scope.__dict__,
    }))
    _docker("build", "--pull=false", "--network=none", "-f",
            "runtime-images/stage1-metering/Dockerfile", "-t", gateway_image, ".",
            timeout=180)
    _docker("build", "--pull=false", "--network=none", "-f",
            "runtime-images/stage1-metering/Dockerfile.mock", "-t", provider_image, ".",
            timeout=180)
    _docker("network", "create", "--internal", internal)
    _docker("network", "create", "--internal", outbound)
    try:
        _docker(
            "run", "-d", "--name", provider, "--network", outbound,
            "--network-alias", "stage1-mock-provider", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "65532:65532", "--env", f"STAGE1_MOCK_MODEL={MODEL}", provider_image,
        )
        _ready(provider)
        _docker(
            "run", "-d", "--name", gateway, "--network", internal,
            "--network-alias", "stage1-metering-gateway", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "65532:65532", "--tmpfs",
            "/stage1-metering:rw,uid=65532,gid=65532,mode=0700,size=1m",
            "--mount", f"type=bind,source={config},target=/stage1-config/config.json,readonly",
            "--env", "STAGE1_MOCK_ONLY=true",
            "--env", "STAGE1_MOCK_UPSTREAM=stage1-mock-provider",
            "--env", f"STAGE1_SYNTHETIC_TOKEN={CANARY}", gateway_image,
        )
        _docker("network", "connect", outbound, gateway)
        _ready(gateway)
        topology = json.loads(_docker("inspect", gateway).stdout)[0]["NetworkSettings"]["Networks"]
        assert set(topology) == {internal, outbound}
        assert json.loads(_docker("network", "inspect", internal).stdout)[0]["Internal"] is True
        assert json.loads(_docker("network", "inspect", outbound).stdout)[0]["Internal"] is True
        bypass = _docker(
            "run", "--rm", "--network", internal, "--read-only",
            "--entrypoint", "/usr/bin/python3", gateway_image,
            "-c", "import socket; socket.create_connection(('stage1-mock-provider', 8443), timeout=2)",
            check=False,
        )
        assert bypass.returncode != 0
        result = _docker(
            "run", "--name", agent, "--network", internal, "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "10001:10001", "--tmpfs", "/tmp:rw,uid=10001,gid=10001,size=16m",
            "--tmpfs", "/nonexistent:rw,uid=10001,gid=10001,size=16m",
            "--env", f"CODEX_API_KEY={CANARY}", "--env", f"CODEX_MODEL={MODEL}",
            AGENT, *codex_metered_argv(MODEL), timeout=120, check=False,
        )
        safe_output = (result.stdout + result.stderr).replace(CANARY, "[REDACTED]")
        if result.returncode:
            current_evidence = _read_bounded_evidence(gateway)
            reason = "no retained metering evidence"
            if current_evidence is not None:
                assert CANARY not in current_evidence
                reason = json.loads(current_evidence).get(
                    "failure_reason", "no failure reason"
                )
            logs = _docker("logs", gateway, check=False)
            denial_codes = [
                line for line in (logs.stdout + logs.stderr).splitlines()
                if line.startswith("STAGE1_DENIAL:") or line == "STAGE1_EVIDENCE_WRITE_FAILED"
            ][:4]
            state = json.loads(_docker("inspect", gateway).stdout)[0]["State"]
            file_state = _docker(
                "exec", gateway, "/usr/bin/python3", "-c",
                "from pathlib import Path; p=Path('/stage1-metering/evidence.json'); "
                "print('present' if p.is_file() else 'absent')",
                check=False,
            )
            pytest.fail(
                f"frozen Codex metering failed: {reason}; "
                f"gateway_running={state['Running']}; "
                f"evidence_state={file_state.stdout.strip()[:20]}; "
                f"evidence_readable={current_evidence is not None}; denial_codes={denial_codes}"
            )
        agent_state = json.loads(_docker("inspect", agent).stdout)[0]
        assert set(agent_state["NetworkSettings"]["Networks"]) == {internal}
        assert agent_state["HostConfig"]["ReadonlyRootfs"] is True
        assert agent_state["Config"]["User"] == "10001:10001"
        assert CANARY not in result.stdout + result.stderr
        assert "mock complete" in safe_output
        evidence = _read_bounded_evidence(gateway)
        assert evidence is not None
        assert CANARY not in evidence
        assert json.loads(evidence)["events"]
        if MODEL == "gpt-5.2-2025-12-11":
            inspection = _docker(
                "exec", provider, "/usr/bin/python3", "-c",
                "import urllib.request; print(urllib.request.urlopen("
                "'http://127.0.0.1:8443/inspection', timeout=2).read().decode())",
            )
            requests = json.loads(inspection.stdout)["requests"]
            assert [request["path"] for request in requests] == [
                "/v1/responses/input_tokens", "/v1/responses",
            ]
            generation = requests[-1]
            assert all(request["model"] == MODEL for request in requests)
            assert generation["stream"] is True
            assert generation["reasoning_effort"] == "none"
            assert generation["reasoning_summary"] is None
            assert generation["verbosity"] is None
            assert generation["parallel_tool_calls"] is True
            assert set(generation["tool_types"]) <= {"function", "custom"}
            assert generation["tool_types"]
            assert generation["tool_names"]
            assert (
                "exec_command" in generation["tool_names"]
                or "functions.exec_command" in generation["tool_names"]
                or "functions" in generation["tool_names"]
            )
            assert "model" in generation["keys"]
            assert "store" in generation["keys"]
            assert "stream" in generation["keys"]
        (tmp_path / "evidence.json").write_text(evidence)
        assert CANARY not in _docker("logs", gateway).stdout
        assert CANARY not in _docker("logs", provider).stdout
    finally:
        _docker("rm", "-f", gateway, provider, agent, check=False)
        _docker("network", "rm", internal, outbound, check=False)
        _docker("image", "rm", gateway_image, provider_image, check=False)
        for name in (gateway, provider, agent):
            assert _docker("inspect", name, check=False).returncode != 0
        for name in (internal, outbound):
            assert _docker("network", "inspect", name, check=False).returncode != 0
        if (tmp_path / "evidence.json").exists():
            assert json.loads((tmp_path / "evidence.json").read_text())["events"]
