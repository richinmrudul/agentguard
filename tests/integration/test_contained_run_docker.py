import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from agentguard.core.contained_run import run_contained_agent_command
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
            pytest.fail("Docker registry access is unavailable for contained-run")
        pytest.skip("Docker registry access is unavailable for contained-run")
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
        pytest.fail("Alpine contained-run image digest did not match the expected pin")
    image = f"amd64/alpine@{digest}"
    pull = _run_docker_control(["docker", "pull", image])
    if pull.returncode != 0:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail("Docker could not pull the digest-pinned contained-run image")
        pytest.skip("Docker could not pull the digest-pinned contained-run image")
    return image


def _platform_claim() -> str:
    info = _run_docker_control(["docker", "info", "--format", "{{json .}}"])
    if info.returncode != 0:
        pytest.skip("Docker info is unavailable")
    payload = json.loads(info.stdout)
    operating_system = str(payload.get("OperatingSystem", "")).lower()
    if "docker desktop" in operating_system:
        return "docker-desktop-experimental"
    return "linux-docker-engine"


def _contained_failure_diagnostic(result) -> str:
    return json.dumps(
        {
            "exit_code": result.exit_code,
            "failure": (
                None
                if result.failure is None
                else {
                    "stage": result.failure.stage,
                    "message": result.failure.message,
                    "exit_code": result.failure.exit_code,
                }
            ),
            "command_result": (
                None
                if result.command_result is None
                else {
                    "exit_code": result.command_result.exit_code,
                    "stdout": result.command_result.stdout,
                    "stderr": result.command_result.stderr,
                    "timed_out": result.command_result.timed_out,
                }
            ),
            "docker_argv": result.docker_argv,
            "report_path": str(result.report_path),
        },
        indent=2,
        sort_keys=True,
    )


@pytest.mark.docker
@pytest.mark.skipif(not docker_available(), reason="Docker is not available")
def test_contained_run_with_hosted_docker_preserves_boundary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    image = _ci_safe_digest_pinned_image()
    source = tmp_path / "source"
    source.mkdir()
    (source / "input.txt").write_text("original\n", encoding="utf-8")
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "task_id": "contained_it",
                "description": "Contained Docker integration.",
                "repo_template": str(source),
                "test_command": "true",
                "expected_modified_files": {"min": 1, "max": 1},
                "max_output_bytes": 4096,
                "sandbox": {
                    "type": "docker",
                    "image": image,
                    "network": "none",
                },
                "contained_execution": {
                    "version": 1,
                    "platform": _platform_claim(),
                    "network": "none",
                    "image_provenance": "digest-required",
                    "required_uid": os.getuid(),
                    "required_gid": os.getgid(),
                    "memory_limit": "128m",
                    "pids_limit": 64,
                    "tmpfs_size": "64k",
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENTGUARD_SECRET_CANARY_HOST_ENV", "must-not-enter")
    uid = os.getuid()
    gid = os.getgid()

    result = run_contained_agent_command(
        config_path,
        [
            "sh",
            "-c",
            (
                "set -eu\n"
                "test \"${AGENTGUARD_SECRET_CANARY_HOST_ENV:-}\" = \"\" && "
                f"test \"$(id -u)\" = \"{uid}\" && "
                f"test \"$(id -g)\" = \"{gid}\" && "
                "printf changed > inside.txt && "
                "test \"$(cat inside.txt)\" = \"changed\" && "
                "printf tmp > /tmp/write-check && "
                "test \"$(cat /tmp/write-check)\" = \"tmp\" && "
                "root_write_blocked=true && "
                "(printf denied > /agentguard-root-denied) 2>/dev/null "
                "&& root_write_blocked=false || true\n"
                "test \"$root_write_blocked\" = \"true\" && "
                "test ! -e .git"
            ),
        ],
        runs_root=tmp_path / "runs",
    )

    assert result.exit_code == 0, _contained_failure_diagnostic(result)
    assert result.preflight.supported is True
    assert result.diff_summary.added_files == ["inside.txt"]
    assert not (source / "inside.txt").exists()
    assert "--env" not in result.docker_argv
    assert "--network" in result.docker_argv
    assert result.docker_argv[result.docker_argv.index("--network") + 1] == "none"
    assert "--read-only" in result.docker_argv
    assert result.docker_argv[result.docker_argv.index("--user") + 1] == f"{uid}:{gid}"
    tmpfs_values = [
        result.docker_argv[index + 1]
        for index, value in enumerate(result.docker_argv)
        if value == "--tmpfs"
    ]
    assert tmpfs_values == [f"/tmp:rw,noexec,nosuid,nodev,size=64k,uid={uid},gid={gid},mode=700"]
    mount = result.docker_argv[result.docker_argv.index("--mount") + 1]
    mount_fields = mount.split(",")
    assert "type=bind" in mount_fields
    assert "target=/agentguard-workspace" in mount_fields
    assert "rw" not in mount_fields
    source_fields = [field for field in mount_fields if field.startswith("source=")]
    assert len(source_fields) == 1
    mounted_workspace = Path(source_fields[0].removeprefix("source="))
    assert mounted_workspace.is_absolute()
    assert mounted_workspace.name == "workspace"
    assert mounted_workspace.parent.name == "agent-workspace"
    assert mounted_workspace != source.resolve()
