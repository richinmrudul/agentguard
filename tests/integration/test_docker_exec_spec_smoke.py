import json
import os
import subprocess
import uuid

import pytest

from agentguard.sandbox.docker_exec_spec import (
    DockerExecSpec,
    build_contained_docker_run_argv,
)
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
            pytest.fail("Docker registry access is unavailable for the exec spec image")
        pytest.skip("Docker registry access is unavailable for the exec spec image")
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
        pytest.fail("Alpine exec spec image digest did not match the expected pin")
    image = f"amd64/alpine@{digest}"
    pull = _run_docker_control(["docker", "pull", image])
    if pull.returncode != 0:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail("Docker could not pull the digest-pinned exec spec image")
        pytest.skip("Docker could not pull the digest-pinned exec spec image")
    return image


def _create_argv_from_run_argv(run_argv: list[str]) -> list[str]:
    assert run_argv[:3] == ["docker", "run", "--rm"]
    return ["docker", "create", *run_argv[3:]]


@pytest.mark.docker
@pytest.mark.skipif(not docker_available(), reason="Docker is not available")
def test_contained_docker_exec_spec_with_hosted_docker() -> None:
    image = _ci_safe_digest_pinned_image()
    container_name = f"agentguard-it-{uuid.uuid4().hex[:12]}"
    script = (
        "set -eu\n"
        'test "$(id -u)" = "1000"\n'
        'test "$(id -g)" = "1000"\n'
        "printf workspace > /workspace/write-check\n"
        "printf tmp > /tmp/write-check\n"
        'test "$(cat /workspace/write-check)" = "workspace"\n'
        'test "$(cat /tmp/write-check)" = "tmp"\n'
        "root_write_blocked=true\n"
        "(printf denied > /agentguard-root-denied) 2>/dev/null "
        "&& root_write_blocked=false || true\n"
        'test "$root_write_blocked" = "true"\n'
        "test ! -e /sys/class/net/eth0\n"
        'printf \'{"uid":%s,"gid":%s,"root_write_blocked":true,"eth0_absent":true}\\n\' '
        '"$(id -u)" "$(id -g)"\n'
    )
    run_argv = build_contained_docker_run_argv(
        DockerExecSpec(
            image=image,
            workspace_host_path=None,
            workspace_container_path="/workspace",
            command=["-c", script],
            uid=1000,
            gid=1000,
            network="none",
            cpu_limit=1.0,
            memory_limit="64m",
            pids_limit=64,
            tmpfs_path="/tmp",
            tmpfs_size="64k",
            workspace_tmpfs_size="64k",
            container_name=container_name,
            entrypoint="/bin/sh",
        )
    )

    assert "--security-opt" in run_argv
    assert "no-new-privileges" in run_argv
    assert "--cap-drop" in run_argv
    assert "ALL" in run_argv
    assert run_argv[run_argv.index("--network") + 1] == "none"
    assert run_argv[run_argv.index("--pids-limit") + 1] == "64"
    assert run_argv[run_argv.index("--memory") + 1] == "64m"
    assert run_argv[run_argv.index("--cpus") + 1] == "1"
    assert "--read-only" in run_argv
    assert "--privileged" not in run_argv
    assert "--device" not in run_argv
    assert "host" not in run_argv
    assert "/var/run/docker.sock" not in run_argv

    create = _run_docker_control(_create_argv_from_run_argv(run_argv))
    try:
        assert create.returncode == 0, create.stderr
        inspect = _run_docker_control(
            ["docker", "container", "inspect", "--format", "{{json .}}", container_name]
        )
        assert inspect.returncode == 0, inspect.stderr
        container = json.loads(inspect.stdout)
        host_config = container["HostConfig"]
        tmpfs = host_config["Tmpfs"]

        assert container["Config"]["User"] == "1000:1000"
        assert host_config["NetworkMode"] == "none"
        assert host_config["ReadonlyRootfs"] is True
        assert host_config["Privileged"] is False
        assert host_config["SecurityOpt"] == ["no-new-privileges"]
        assert host_config["CapDrop"] == ["ALL"]
        assert host_config["PidsLimit"] == 64
        assert host_config["Memory"] == 64 * 1024 * 1024
        assert host_config["NanoCpus"] == 1_000_000_000
        assert host_config.get("Devices") in (None, [])
        assert host_config.get("Binds") in (None, [])
        assert host_config.get("PidMode", "") != "host"
        assert host_config.get("IpcMode", "") != "host"
        assert host_config.get("UsernsMode", "") != "host"
        assert "/tmp" in tmpfs
        assert "/workspace" in tmpfs
        assert "uid=1000" in tmpfs["/workspace"]
        assert "gid=1000" in tmpfs["/workspace"]

        start = _run_docker_control(["docker", "start", "-a", container_name])
        assert start.returncode == 0, start.stderr
        observed = json.loads(start.stdout)
        assert observed == {
            "uid": 1000,
            "gid": 1000,
            "root_write_blocked": True,
            "eth0_absent": True,
        }
    finally:
        _run_docker_control(["docker", "rm", "-f", container_name])
