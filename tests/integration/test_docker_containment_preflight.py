import os
from dataclasses import replace
from pathlib import Path

import pytest

from agentguard.config.loader import load_config
from agentguard.config.schema import ContainedExecutionConfig, SandboxConfig
from agentguard.sandbox.docker_preflight import DockerPreflightStatus, run_docker_preflight
from agentguard.sandbox.docker_runner import docker_available


@pytest.mark.docker
@pytest.mark.skipif(not docker_available(), reason="Docker is not available")
def test_docker_preflight_with_hosted_docker_when_image_is_provided() -> None:
    image = os.environ.get("AGENTGUARD_PREFLIGHT_IMAGE")
    if not image:
        pytest.skip("AGENTGUARD_PREFLIGHT_IMAGE is not set to a local digest-pinned non-root image")

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
