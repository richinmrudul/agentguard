import json
import os
import subprocess
from pathlib import Path
from typing import Optional

import pytest
import yaml

from agentguard.core.contained_run import run_contained_agent_command
from agentguard.core import contained_run
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


def _require_docker_available() -> None:
    if docker_available():
        return
    if os.environ.get("GITHUB_ACTIONS"):
        pytest.fail("Docker is not available for contained-run integration coverage")
    pytest.skip("Docker is not available")


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
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail("Docker info is unavailable")
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
def test_contained_run_with_hosted_docker_preserves_boundary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _require_docker_available()
    image = _ci_safe_digest_pinned_image()
    path_canary = "AGENTGUARD_SECRET_CANARY_PATH_157"
    source = tmp_path / f"source-{path_canary}"
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
                    "environment": [
                        {"name": "ALLOWED_VALUE", "value": "inside"},
                        {
                            "name": "API_TOKEN",
                            "value": "docker-secret-canary",
                            "allow_sensitive": True,
                        },
                    ],
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
                "test \"${DOCKER_HOST:-}\" = \"\" && "
                "test \"${SSH_AUTH_SOCK:-}\" = \"\" && "
                "test \"${ALLOWED_VALUE:-}\" = \"inside\" && "
                "test \"${API_TOKEN:-}\" = \"docker-secret-canary\" && "
                "test \"${HOME:-}\" = \"/tmp/agentguard-home\" && "
                "test \"${LANG:-}\" = \"C.UTF-8\" && "
                "test \"${LC_ALL:-}\" = \"C.UTF-8\" && "
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
    assert "--env" in result.docker_argv
    assert "ALLOWED_VALUE=[REDACTED]" in result.docker_argv
    assert "API_TOKEN=[REDACTED]" in result.docker_argv
    assert "docker-secret-canary" not in json.dumps(result.docker_argv)
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
    diagnostic_source = source_fields[0].removeprefix("source=")
    assert "[REDACTED]" in diagnostic_source
    assert diagnostic_source.endswith("/workspace-lifecycle/agent-workspace/workspace")
    assert str(tmp_path) not in mount
    assert str(source.resolve()) not in mount
    assert "/home/" not in diagnostic_source
    assert "/Users/" not in diagnostic_source
    assert "/private/" not in diagnostic_source
    assert not diagnostic_source.startswith("/")
    assert path_canary not in mount
    assert "must-not-enter" not in mount
    report = json.loads(result.report_path.read_text(encoding="utf-8"))
    evidence = report["containment_evidence"]
    assert evidence["execution_mode"] == "contained-run"
    assert evidence["preflight"]["status"] in {"supported", "experimental"}
    assert evidence["image"]["registry_digest"] == f"amd64/alpine@{ALPINE_AMD64_DIGEST}"
    assert evidence["image"]["container_bound_image_id"].startswith("sha256:")
    assert evidence["controls"]["read_only_root"] is True
    assert evidence["environment"]["sensitive_names"] == ["API_TOKEN"]
    assert evidence["environment"]["values_recorded"] is False
    assert evidence["cleanup"]["overall_complete"] is True
    serialized_evidence = json.dumps(evidence, sort_keys=True)
    assert "docker-secret-canary" not in serialized_evidence
    assert str(tmp_path) not in serialized_evidence


@pytest.mark.docker
@pytest.mark.parametrize(
    ("source_path", "destination_path", "expected_result", "expected_failed_check"),
    [
        ("src/ok.txt", "src/renamed.txt", "PASS", None),
        ("secrets/token.txt", "src/token.txt", "FAIL", "Forbidden paths"),
        ("src/ok.txt", "secrets/ok.txt", "FAIL", "Forbidden paths"),
    ],
)
def test_hosted_docker_contained_run_applies_rename_endpoint_policy(
    tmp_path: Path,
    source_path: str,
    destination_path: str,
    expected_result: str,
    expected_failed_check: Optional[str],
) -> None:
    _require_docker_available()
    image = _ci_safe_digest_pinned_image()
    source = tmp_path / f"source-rename-{expected_result.lower()}-{source_path.split('/')[0]}"
    (source / "src").mkdir(parents=True)
    (source / "secrets").mkdir()
    (source / "src" / "ok.txt").write_text("safe\n", encoding="utf-8")
    (source / "secrets" / "token.txt").write_text("protected\n", encoding="utf-8")
    config_path = tmp_path / f"rename-{expected_result.lower()}-{destination_path.replace('/', '-')}.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "task_id": "contained_docker_rename_policy",
                "description": "Contained Docker rename endpoint policy.",
                "repo_template": str(source),
                "test_command": "true",
                "allowed_paths": ["src/**"],
                "forbidden_paths": ["secrets/**"],
                "test_paths": ["tests/**"],
                "secret_patterns": ["secrets/**"],
                "expected_modified_files": {"min": 0, "max": 4},
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

    result = run_contained_agent_command(
        config_path,
        [
            "sh",
            "-c",
            (
                "set -eu\n"
                f"mkdir -p {destination_path.rsplit('/', 1)[0]}\n"
                f"mv {source_path} {destination_path}\n"
            ),
        ],
        runs_root=tmp_path / "runs",
    )

    assert result.result == expected_result, _contained_failure_diagnostic(result)
    assert result.diff_summary.renamed_files[0].source_path == source_path
    assert result.diff_summary.renamed_files[0].destination_path == destination_path
    assert (source / source_path).exists()
    assert not (source / destination_path).exists()
    if expected_failed_check is not None:
        check = next(item for item in result.check_results if item.name == expected_failed_check)
        assert check.passed is False


def _base_config(tmp_path: Path, *, image: str, task_id: str) -> tuple[Path, Path]:
    source = tmp_path / f"source-{task_id}"
    source.mkdir()
    (source / "input.txt").write_text("original\n", encoding="utf-8")
    config_path = tmp_path / f"{task_id}.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "task_id": task_id,
                "description": "Contained Docker cleanup integration.",
                "repo_template": str(source),
                "test_command": "true",
                "command_timeout_seconds": 1,
                "expected_modified_files": {"min": 0, "max": 1},
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
    return config_path, source


def _agentguard_owned_container_ids() -> set[str]:
    completed = _run_docker_control(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            "label=agentguard.owner=contained-run",
            "--format",
            "{{.ID}}",
        ]
    )
    if completed.returncode != 0:
        pytest.fail("Docker could not list AgentGuard-owned containers")
    return {line.strip() for line in completed.stdout.splitlines() if line.strip()}


def _container_exists(name: str) -> bool:
    completed = _run_docker_control(
        ["docker", "container", "inspect", "--format", "{{.Id}}", name]
    )
    return completed.returncode == 0


def _create_unrelated_similarly_named_container(image: str, name: str) -> None:
    completed = _run_docker_control(
        [
            "docker",
            "create",
            "--name",
            name,
            "--label",
            "agentguard.owner=unrelated-test",
            "--",
            image,
            "sh",
            "-c",
            "sleep 60",
        ]
    )
    if completed.returncode != 0:
        pytest.fail(f"Could not create unrelated Docker control container: {completed.stderr}")


@pytest.mark.docker
def test_contained_run_timeout_cleans_owned_container_and_leaves_unrelated(
    tmp_path: Path,
) -> None:
    _require_docker_available()
    image = _ci_safe_digest_pinned_image()
    config_path, source = _base_config(
        tmp_path,
        image=image,
        task_id="contained_timeout_cleanup_it",
    )
    unrelated_name = "agentguard-contained-timeout-cleanup-unrelated"
    before_owned = _agentguard_owned_container_ids()
    _create_unrelated_similarly_named_container(image, unrelated_name)
    assert _container_exists(unrelated_name)

    try:
        result = run_contained_agent_command(
            config_path,
            [
                "sh",
                "-c",
                (
                    "set -eu\n"
                    "printf started > timeout-marker.txt\n"
                    "sleep 20"
                ),
            ],
            runs_root=tmp_path / "runs",
        )

        report = json.loads(result.report_path.read_text(encoding="utf-8"))
        serialized = json.dumps(report, sort_keys=True)
        after_owned = _agentguard_owned_container_ids()

        assert result.result == "FAIL", _contained_failure_diagnostic(result)
        assert result.exit_code == contained_run.EXIT_TIMEOUT
        assert result.failure is not None
        assert result.failure.exit_code == contained_run.EXIT_TIMEOUT
        assert result.command_result is not None
        assert result.command_result.timed_out is True
        assert result.cleanup.attempted is True
        assert result.cleanup.complete is True
        assert result.cleanup.status in {
            "removed",
            "cleanly_terminated",
            "force_killed",
            "already_absent",
        }
        assert report["result"] == "FAIL"
        assert report["cleanup"]["attempted"] is True
        assert report["cleanup"]["complete"] is True
        assert report["cleanup"]["status"] in {
            "removed",
            "cleanly_terminated",
            "force_killed",
            "already_absent",
        }
        assert after_owned == before_owned
        assert _container_exists(unrelated_name)
        assert str(tmp_path) not in serialized
        assert str(source.resolve()) not in serialized
        assert "/Users/" not in serialized
        assert "/home/" not in serialized
        assert "/private/" not in serialized
        assert "agentguard-contained-timeout-cleanup-unrelated" not in serialized
        assert "agentguard.contained-run.id=[REDACTED]" in serialized
        assert "agentguard-[REDACTED]" in serialized
    finally:
        _run_docker_control(["docker", "rm", "-f", unrelated_name])
