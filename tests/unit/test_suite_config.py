from pathlib import Path

import pytest
import yaml

from agentguard.core.suite import load_suite_config


def test_load_suite_config_loads_valid_yaml(tmp_path: Path) -> None:
    suite_path = tmp_path / "suite.yaml"
    suite_path.write_text(
        "suite_id: tiny\n"
        "description: Tiny suite.\n"
        "runs:\n"
        "  - config: examples/configs/fix_auth_bug.yaml\n"
        "    agent: mock-safe\n",
        encoding="utf-8",
    )

    config = load_suite_config(suite_path)

    assert config.suite_id == "tiny"
    assert config.description == "Tiny suite."
    assert config.suite_path == suite_path.resolve()
    assert len(config.runs) == 1
    assert config.runs[0].config_path == Path("examples/configs/fix_auth_bug.yaml")
    assert config.runs[0].agent == "mock-safe"


def test_load_suite_config_rejects_empty_runs(tmp_path: Path) -> None:
    suite_path = tmp_path / "suite.yaml"
    suite_path.write_text(
        "suite_id: tiny\n"
        "description: Tiny suite.\n"
        "runs: []\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="runs"):
        load_suite_config(suite_path)


def test_load_suite_config_rejects_missing_run_config(tmp_path: Path) -> None:
    suite_path = tmp_path / "suite.yaml"
    suite_path.write_text(
        "suite_id: tiny\n"
        "description: Tiny suite.\n"
        "runs:\n"
        "  - agent: mock-safe\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="config"):
        load_suite_config(suite_path)


def test_load_suite_config_rejects_missing_run_agent(tmp_path: Path) -> None:
    suite_path = tmp_path / "suite.yaml"
    suite_path.write_text(
        "suite_id: tiny\n"
        "description: Tiny suite.\n"
        "runs:\n"
        "  - config: examples/configs/fix_auth_bug.yaml\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="agent"):
        load_suite_config(suite_path)


def test_suite_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    suite_path = tmp_path / "duplicate.yaml"
    suite_path.write_text(
        "suite_id: first\n"
        "suite_id: second\n"
        "description: Duplicate key.\n"
        "runs:\n"
        "  - config: config.yaml\n"
        "    agent: mock-safe\n",
        encoding="utf-8",
    )

    with pytest.raises(yaml.YAMLError, match="duplicate key 'suite_id'"):
        load_suite_config(suite_path)


@pytest.mark.parametrize(
    ("typo", "path", "suggestion"),
    [
        ("descripton: Typo.\n", "descripton", "description"),
        (
            "runs:\n"
            "  - configg: examples/configs/fix_auth_bug.yaml\n"
            "    agent: mock-safe\n",
            "runs\\[0\\].configg",
            "runs[0].config",
        ),
    ],
)
def test_suite_rejects_unknown_fields_with_suggestions(
    tmp_path: Path,
    typo: str,
    path: str,
    suggestion: str,
) -> None:
    suite_path = tmp_path / "suite.yaml"
    body = (
        "suite_id: tiny\n"
        "description: Tiny suite.\n"
        "runs:\n"
        "  - config: examples/configs/fix_auth_bug.yaml\n"
        "    agent: mock-safe\n"
    )
    if typo.startswith("runs:"):
        body = body[: body.index("runs:")] + typo
    else:
        body += typo
    suite_path.write_text(body, encoding="utf-8")

    with pytest.raises(ValueError, match=path) as error:
        load_suite_config(suite_path)

    assert f"Did you mean '{suggestion}'?" in str(error.value)
