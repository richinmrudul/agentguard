from dataclasses import replace
from pathlib import Path

import pytest

from agentguard.artifact_paths import artifact_directory, validate_artifact_id
from agentguard.config.loader import load_config
from agentguard.core.benchmark import _summary_dir
from agentguard.core.ci import _run_dir
from agentguard.core.matrix import _matrix_dir
from agentguard.core.suite import _suite_dir, load_suite_config
from agentguard.repo.manager import RepoManager


MALICIOUS_IDS = [
    "/tmp/AGENTGUARD_PATH_CANARY",
    "../AGENTGUARD_PATH_CANARY",
    "nested/AGENTGUARD_PATH_CANARY",
    r"..\AGENTGUARD_PATH_CANARY",
    r"C:\AGENTGUARD_PATH_CANARY",
    r"\\server\share\AGENTGUARD_PATH_CANARY",
    "AGENTGUARD_PATH_CANARY\nnext",
    "AGENTGUARD_PATH_CANARY\x00next",
]


@pytest.mark.parametrize("identifier", MALICIOUS_IDS)
def test_artifact_ids_reject_nonportable_path_syntax(identifier: str) -> None:
    with pytest.raises(ValueError, match="portable characters"):
        validate_artifact_id(identifier, "identifier")


@pytest.mark.parametrize(
    "identifier",
    ["task", "fix_auth_bug", "suite-1", "release.2026_07"],
)
def test_artifact_ids_accept_existing_portable_forms(identifier: str) -> None:
    assert validate_artifact_id(identifier, "identifier") == identifier


@pytest.mark.parametrize(
    ("builder", "args"),
    [
        (_run_dir, ("bad/task", Path("repo"), Path("ci"))),
        (_summary_dir, ("bad/task", Path("benchmarks"))),
        (_suite_dir, ("bad/suite", Path("suites"))),
        (_matrix_dir, ("bad/matrix", Path("matrices"))),
    ],
)
def test_all_artifact_builders_reject_separator_components(builder, args) -> None:
    with pytest.raises(ValueError, match="portable path component"):
        builder(*args)


def test_artifact_directory_resolves_below_root(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"

    candidate = artifact_directory(root, "task-20260723-deadbeef")

    assert candidate.resolve().is_relative_to(root.resolve())


@pytest.mark.parametrize("task_id", MALICIOUS_IDS)
def test_config_rejects_malicious_task_id_without_creating_artifacts(
    tmp_path: Path,
    task_id: str,
) -> None:
    config_path = tmp_path / "agentguard.yaml"
    artifact_root = tmp_path / "artifacts"
    config_path.write_text(
        "task_id: " + repr(task_id) + "\n"
        "description: Path containment test.\n"
        "mode: ci\n"
        "test_command: pytest\n"
        "expected_modified_files:\n"
        "  min: 0\n"
        "  max: 1\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_config(config_path)

    assert not artifact_root.exists()


@pytest.mark.parametrize("suite_id", MALICIOUS_IDS)
def test_suite_rejects_malicious_id_without_creating_artifacts(
    tmp_path: Path,
    suite_id: str,
) -> None:
    suite_path = tmp_path / "suite.yaml"
    artifact_root = tmp_path / "artifacts"
    suite_path.write_text(
        "suite_id: " + repr(suite_id) + "\n"
        "description: Path containment test.\n"
        "runs:\n"
        "  - config: task.yaml\n"
        "    agent: mock-safe\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_suite_config(suite_path)

    assert not artifact_root.exists()


def test_repo_manager_rejects_tampered_task_id_before_creating_root(
    tmp_path: Path,
) -> None:
    config = replace(
        load_config(Path("examples/configs/fix_auth_bug.yaml")),
        task_id="../AGENTGUARD_PATH_CANARY",
    )
    runs_root = tmp_path / "runs"

    with pytest.raises(ValueError, match="portable path component"):
        RepoManager(runs_root).prepare(config, "mock-safe")

    assert not runs_root.exists()
