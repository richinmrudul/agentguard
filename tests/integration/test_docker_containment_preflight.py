import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from agentguard.config.loader import load_config
from agentguard.config.schema import ContainedExecutionConfig, SandboxConfig
from agentguard.sandbox.docker_preflight import DockerPreflightStatus, run_docker_preflight
from agentguard.sandbox.docker_runner import docker_available


ALPINE_AMD64_TAG = "amd64/alpine:3.20.10"
ALPINE_AMD64_DIGEST = (
    "sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e"
)


def _run_docker_control(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _ci_safe_digest_pinned_image() -> str:
    manifest = _run_docker_control(
        ["docker", "manifest", "inspect", "--verbose", ALPINE_AMD64_TAG]
    )
    if manifest.returncode != 0:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail("Docker registry access is unavailable for the preflight image")
        pytest.skip("Docker registry access is unavailable for the preflight image")
    try:
        manifest_data = json.loads(manifest.stdout)
    except json.JSONDecodeError:
        pytest.skip("Docker manifest response was not JSON")
    if not isinstance(manifest_data, list):
        manifest_data = [manifest_data]
    digest = None
    for item in manifest_data:
        if not isinstance(item, dict):
            continue
        descriptor = item.get("Descriptor", {})
        platform = descriptor.get("platform", {}) if isinstance(descriptor, dict) else {}
        if platform.get("os") == "linux" and platform.get("architecture") == "amd64":
            digest = descriptor.get("digest")
            break
    if digest != ALPINE_AMD64_DIGEST:
        pytest.fail("Alpine preflight image digest did not match the expected pin")
    image = f"amd64/alpine@{digest}"
    pull = _run_docker_control(["docker", "pull", image])
    if pull.returncode != 0:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail("Docker could not pull the digest-pinned preflight image")
        pytest.skip("Docker could not pull the digest-pinned preflight image")
    return image


@pytest.mark.docker
@pytest.mark.skipif(not docker_available(), reason="Docker is not available")
def test_docker_preflight_with_hosted_docker() -> None:
    image = _ci_safe_digest_pinned_image()

    config = replace(
        load_config(Path("examples/configs/fix_auth_bug_docker.yaml")),
        sandbox=SandboxConfig(
            type="docker",
            image=image,
            network="none",
            memory="128m",
            cpus=1.0,
            read_only=True,
        ),
        contained_execution=ContainedExecutionConfig(
            version=1,
            platform="linux-docker-engine",
            network="none",
            image_provenance="digest-required",
        ),
    )

    result = run_docker_preflight(config)

    assert result.status == DockerPreflightStatus.SUPPORTED
    assert result.docker_image is not None
    assert result.checks[-1].name == "uid_gid_writable_path_probe"
