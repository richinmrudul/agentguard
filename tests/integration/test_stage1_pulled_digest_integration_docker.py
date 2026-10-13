from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from agentguard.sandbox.docker_runner import docker_available


ROOT = Path(__file__).resolve().parents[2]
REGISTRY_IMAGE = (
    "registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
)


def _run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _require_docker() -> None:
    if not docker_available():
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail("Docker is required for Stage 1 pulled-digest integration coverage")
        pytest.skip("Docker is not available")
    if shutil.which("cc") is None:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail("A C compiler is required for Stage 1 pulled-digest integration coverage")
        pytest.skip("A C compiler is not available")


def _docker_or_skip(
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    result = _run(argv, cwd=cwd, timeout=timeout)
    if result.returncode != 0:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail(
                "Docker command failed: "
                + json.dumps(
                    {
                        "argv": argv,
                        "stdout": result.stdout[-1000:],
                        "stderr": result.stderr[-1000:],
                    },
                    sort_keys=True,
                )
            )
        pytest.skip("Docker command failed in local environment: " + result.stderr[-500:])
    return result


def _start_registry(tmp_path: Path) -> tuple[str, str]:
    name = "agentguard-stage1-local-registry-" + tmp_path.name[-12:]
    _docker_or_skip(["docker", "pull", REGISTRY_IMAGE], timeout=180)
    run = _docker_or_skip(
        [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                name,
            "-p",
                "127.0.0.1::5000",
                REGISTRY_IMAGE,
        ],
        timeout=60,
    )
    (tmp_path / "registry-container-id.txt").write_text(run.stdout.strip(), encoding="utf-8")
    inspect = _docker_or_skip(
        [
            "docker",
            "inspect",
            "--format",
            "{{(index (index .NetworkSettings.Ports \"5000/tcp\") 0).HostPort}}",
            name,
        ],
        timeout=30,
    )
    port = inspect.stdout.strip()
    assert port.isdigit()
    return name, f"127.0.0.1:{port}"


def _build_gateway(registry: str) -> str:
    tag = f"{registry}/agentguard-stage1-gateway:test"
    build = _docker_or_skip(
        [
            "docker",
            "build",
            "--platform",
            "linux/amd64",
            "--build-arg",
            "SOURCE_COMMIT=037aa62c0926e3210d8897b19d75819f5f73f692",
            "-t",
            tag,
            "runtime-images/gateway",
        ],
        cwd=ROOT,
        timeout=240,
    )
    assert "Successfully" in build.stdout or build.returncode == 0
    _docker_or_skip(["docker", "push", tag], timeout=180)
    digest = _digest_for_tag(tag)
    return f"{registry}/agentguard-stage1-gateway@{digest}"


def _build_agent(tmp_path: Path, registry: str) -> str:
    context = tmp_path / "agent"
    context.mkdir()
    source = context / "agent.c"
    binary = context / "agent"
    source.write_text(
        textwrap.dedent(
            r"""
            #include <stdio.h>
            #include <string.h>

            int main(int argc, char **argv) {
              if (argc == 2 && strcmp(argv[1], "--version") == 0) {
                puts("codex-cli 0.159.2");
                return 0;
              }
              return 2;
            }
            """
        ),
        encoding="utf-8",
    )
    compile_result = _run(["cc", "-static", "-O2", "-s", "-o", str(binary), str(source)], timeout=90)
    if compile_result.returncode != 0:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail("Failed to compile static mock agent: " + compile_result.stderr)
        pytest.skip("Static mock agent compilation is unavailable")
    (context / "Dockerfile").write_text(
        'FROM scratch\nCOPY agent /agent\nUSER 10001:10001\nENTRYPOINT ["/agent"]\n',
        encoding="utf-8",
    )
    tag = f"{registry}/agentguard-stage1-agent:test"
    _docker_or_skip(["docker", "build", "--network", "none", "-t", tag, "."], cwd=context, timeout=120)
    _docker_or_skip(["docker", "push", tag], timeout=120)
    digest = _digest_for_tag(tag)
    return f"{registry}/agentguard-stage1-agent@{digest}"


def _digest_for_tag(tag: str) -> str:
    inspect = _docker_or_skip(["docker", "buildx", "imagetools", "inspect", tag], timeout=60)
    for line in inspect.stdout.splitlines():
        if line.strip().startswith("Digest:"):
            digest = line.split(":", 1)[1].strip()
            assert digest.startswith("sha256:")
            return digest
    pytest.fail("digest not found for " + tag)


def _containers_with_prefix(prefix: str) -> list[str]:
    result = _run(["docker", "ps", "-a", "--format", "{{.Names}}"], timeout=30)
    assert result.returncode == 0
    return [name for name in result.stdout.splitlines() if name.startswith(prefix)]


@pytest.mark.docker
def test_stage1_pulled_digest_integration_uses_real_gateway_evidence_lifecycle(
    tmp_path: Path,
) -> None:
    _require_docker()
    registry_name, registry = _start_registry(tmp_path)
    output = tmp_path / "mock-egress-pulled-digest.json"
    try:
        gateway_ref = _build_gateway(registry)
        agent_ref = _build_agent(tmp_path, registry)

        result = _docker_or_skip(
            [
                sys.executable,
                "scripts/stage1_pulled_digest_integration.py",
                "--gateway-ref",
                gateway_ref,
                "--agent-ref",
                agent_ref,
                "--gateway-identity",
                "sha256:" + "1" * 64,
                "--agent-identity",
                "sha256:" + "2" * 64,
                "--output",
                str(output),
            ],
            cwd=ROOT,
            timeout=180,
        )
        assert result.returncode == 0
        payload = json.loads(output.read_text(encoding="utf-8"))
        assert payload["status"] == "passed"
        assert payload["gateway_ref"] == gateway_ref
        assert payload["agent_ref"] == agent_ref
        assert payload["checks"]["read_only_root"] is True
        assert payload["checks"]["approved_local_mock_destination"] is True
        assert payload["checks"]["disallowed_destination_denied"] is True
        assert payload["checks"]["direct_bypass_denied"] is True
        assert payload["checks"]["metadata_destination_denied"] is True
        assert payload["checks"]["credential_canary_not_retained"] is True
        assert payload["checks"]["gateway_evidence_bounded_and_sanitized"] is True
        evidence = payload["gateway_evidence"]
        assert evidence["uid"] == 65532
        assert evidence["gid"] == 65532
        assert evidence["mode"] == "0o644"
        assert 0 < evidence["size"] <= 1024 * 1024
        serialized = json.dumps(payload, sort_keys=True)
        assert "AGENTGUARD_STAGE1_PUBLICATION_CANARY_310" not in serialized
        assert "api.openai.com" not in serialized
        assert not _containers_with_prefix("ag-stage1-")
    finally:
        _run(["docker", "rm", "-f", registry_name], timeout=30)
        remaining = _run(["docker", "ps", "-a", "--format", "{{.Names}}"], timeout=30)
        assert registry_name not in remaining.stdout.splitlines()
