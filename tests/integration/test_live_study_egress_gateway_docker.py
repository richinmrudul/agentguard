import json
import os
import subprocess
from pathlib import Path

import pytest

from agentguard.config.docker_image import validate_docker_image_reference
from agentguard.evaluation.live_egress_gateway import (
    EgressDestinationRule,
    LiveStudyEgressPolicy,
    build_live_study_egress_docker_plan,
    evaluate_live_study_egress_destination,
    record_blocked_route,
    run_live_study_egress_docker_plan,
)
from agentguard.sandbox.docker_runner import docker_available


LOCAL_IMAGE_ENV = "AGENTGUARD_LOCAL_MOCK_EGRESS_IMAGE"


def _docker(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _require_local_digest_image() -> str:
    if not docker_available():
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail("Docker is required for live study-egress gateway integration coverage")
        pytest.skip("Docker is not available")
    image = os.environ.get(LOCAL_IMAGE_ENV)
    if not image:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail(f"{LOCAL_IMAGE_ENV} must name a preloaded digest-pinned local mock image")
        pytest.skip(f"{LOCAL_IMAGE_ENV} is not configured")
    validate_docker_image_reference(image)
    if "@sha256:" not in image:
        pytest.fail(f"{LOCAL_IMAGE_ENV} must be digest-pinned")
    inspect = _docker(["docker", "image", "inspect", image])
    if inspect.returncode != 0:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail(f"{LOCAL_IMAGE_ENV} image is not preloaded locally")
        pytest.skip(f"{LOCAL_IMAGE_ENV} image is not preloaded locally")
    return image


@pytest.mark.docker
def test_live_study_egress_gateway_docker_topology_crash_and_cleanup(
    tmp_path: Path,
) -> None:
    image = _require_local_digest_image()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    policy = LiveStudyEgressPolicy(
        destinations=(
            EgressDestinationRule("mock-approved.test", 443, test_only=True),
        )
    )
    assert (
        evaluate_live_study_egress_destination(
            policy,
            host="mock-approved.test",
            port=443,
            protocol="https",
            resolved_addresses=["203.0.113.10"],
        )["decision"]
        == "allow"
    )
    assert record_blocked_route(route_kind="direct-outbound")["decision"] == "deny"

    plan = build_live_study_egress_docker_plan(
        trial_id="trial-0123456789abcdef01234567",
        agent_image=image,
        gateway_image=image,
        workspace_host_path=workspace,
        agent_command=["sh", "-c", "exit 0"],
        gateway_command=["sh", "-c", "exit 7"],
        uid=os.getuid() or 1000,
        gid=os.getgid() or 1000,
        run_token="fedcba654321",
    )
    assert "--internal" in plan.commands["create_internal_network"]
    assert plan.outbound_network not in plan.commands["create_agent"]

    result = run_live_study_egress_docker_plan(plan)

    assert result["status"] == "failed"
    assert result["failure_step"] == "gateway_liveness"
    assert result["cleanup"]["overall_complete"] is True
    for target in [
        plan.agent_container,
        plan.gateway_container,
        plan.internal_network,
        plan.outbound_network,
    ]:
        kind = "network" if target in {plan.internal_network, plan.outbound_network} else "container"
        inspect = _docker(["docker", kind, "inspect", target])
        assert inspect.returncode != 0, json.dumps(
            {
                "target": target,
                "stdout": inspect.stdout,
                "stderr": inspect.stderr,
            },
            sort_keys=True,
        )
