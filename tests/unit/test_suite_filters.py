from pathlib import Path

import pytest

from agentguard.core.suite import (
    SuiteFilters,
    SuiteRunConfig,
    filter_suite_runs,
    normalize_filter_tags,
)


def _write_config(
    path: Path,
    *,
    task_id: str,
    category: str,
    difficulty: str,
    tags: list[str],
) -> None:
    tag_lines = "\n".join(f"    - {tag}" for tag in tags)
    path.write_text(
        f"""
task_id: {task_id}
description: Filter test config.
repo_template: examples/repos/auth_bug
test_command: pytest
benchmark:
  id: {task_id}
  category: {category}
  difficulty: {difficulty}
  tags:
{tag_lines}
expected_modified_files:
  min: 1
  max: 2
""",
        encoding="utf-8",
    )


def _runs(tmp_path: Path) -> list[SuiteRunConfig]:
    source_config = tmp_path / "source.yaml"
    prompt_config = tmp_path / "prompt.yaml"
    _write_config(
        source_config,
        task_id="source_fix_task",
        category="source_fix",
        difficulty="easy",
        tags=["docker", "python"],
    )
    _write_config(
        prompt_config,
        task_id="prompt_task",
        category="prompt_injection",
        difficulty="medium",
        tags=["docker", "python", "secret-access"],
    )
    return [
        SuiteRunConfig(config_path=source_config, agent="mock-safe"),
        SuiteRunConfig(config_path=prompt_config, agent="mock-safe"),
    ]


def test_normalize_filter_tags_supports_repeated_and_comma_separated() -> None:
    assert normalize_filter_tags(["docker, secret-access", "python"]) == [
        "docker",
        "secret-access",
        "python",
    ]


def test_filter_suite_runs_by_category(tmp_path: Path) -> None:
    matched = filter_suite_runs(_runs(tmp_path), SuiteFilters(category="source_fix"))

    assert [run.config_path.name for run in matched] == ["source.yaml"]


def test_filter_suite_runs_by_difficulty(tmp_path: Path) -> None:
    matched = filter_suite_runs(_runs(tmp_path), SuiteFilters(difficulty="medium"))

    assert [run.config_path.name for run in matched] == ["prompt.yaml"]


def test_filter_suite_runs_by_one_tag(tmp_path: Path) -> None:
    matched = filter_suite_runs(_runs(tmp_path), SuiteFilters(tags=["secret-access"]))

    assert [run.config_path.name for run in matched] == ["prompt.yaml"]


def test_filter_suite_runs_by_multiple_tags_uses_and_semantics(tmp_path: Path) -> None:
    matched = filter_suite_runs(
        _runs(tmp_path),
        SuiteFilters(tags=["docker", "secret-access"]),
    )

    assert [run.config_path.name for run in matched] == ["prompt.yaml"]


def test_filter_suite_runs_zero_matches_raises_clean_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="suite filters matched no runs"):
        filter_suite_runs(_runs(tmp_path), SuiteFilters(category="unsafe_command"))
