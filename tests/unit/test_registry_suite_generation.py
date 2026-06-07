from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from agentguard.benchmarks.registry import (
    generate_suite_data,
    load_benchmark_registry,
    write_generated_suite,
)
from agentguard.cli.main import app
from agentguard.core.suite import load_suite_config


runner = CliRunner()


def _write_registry(tmp_path: Path) -> Path:
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    for name in [
        "auth_safe.yaml",
        "auth_adversarial.yaml",
        "prompt_safe.yaml",
        "prompt_adversarial.yaml",
    ]:
        (config_dir / name).write_text(f"task_id: {name}\n", encoding="utf-8")
    contract_dir = tmp_path / "contracts"
    contract_dir.mkdir()
    (contract_dir / "auth_bug.yaml").write_text("{}\n", encoding="utf-8")
    (contract_dir / "prompt_injection_readme.yaml").write_text(
        "{}\n",
        encoding="utf-8",
    )

    registry_path = tmp_path / "registry.yaml"
    registry_path.write_text(
        """
benchmarks:
  - id: auth_bug
    version: 1
    name: Auth Login Bug
    category: test_tampering
    difficulty: easy
    description: Auth benchmark.
    tags:
      - python
      - docker
      - test-tampering
    configs:
      safe: configs/auth_safe.yaml
      adversarial: configs/auth_adversarial.yaml
    contract: contracts/auth_bug.yaml
  - id: prompt_injection_readme
    version: 1
    name: Prompt Injection README
    category: prompt_injection
    difficulty: medium
    description: Prompt injection benchmark.
    tags:
      - python
      - docker
      - prompt-injection
      - secret-access
    configs:
      safe: configs/prompt_safe.yaml
      adversarial: configs/prompt_adversarial.yaml
    contract: contracts/prompt_injection_readme.yaml
""",
        encoding="utf-8",
    )
    return registry_path


def _load_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    registry_path = _write_registry(tmp_path)
    monkeypatch.chdir(tmp_path)
    return load_benchmark_registry(registry_path), registry_path


def _configs(suite_data: dict) -> list[str]:
    return [run["config"] for run in suite_data["runs"]]


def test_generate_suite_includes_all_configs_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry, _ = _load_registry(tmp_path, monkeypatch)

    suite_data = generate_suite_data(
        registry,
        suite_id="registry_core",
        description="Generated.",
    )

    assert _configs(suite_data) == [
        "configs/auth_safe.yaml",
        "configs/auth_adversarial.yaml",
        "configs/prompt_safe.yaml",
        "configs/prompt_adversarial.yaml",
    ]


def test_generate_suite_with_include_safe_includes_only_safe_configs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry, _ = _load_registry(tmp_path, monkeypatch)

    suite_data = generate_suite_data(
        registry,
        suite_id="registry_core",
        description="Generated.",
        include=["safe"],
    )

    assert _configs(suite_data) == [
        "configs/auth_safe.yaml",
        "configs/prompt_safe.yaml",
    ]


def test_include_order_is_preserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry, _ = _load_registry(tmp_path, monkeypatch)

    suite_data = generate_suite_data(
        registry,
        suite_id="registry_core",
        description="Generated.",
        include=["adversarial,safe"],
    )

    assert _configs(suite_data) == [
        "configs/auth_adversarial.yaml",
        "configs/auth_safe.yaml",
        "configs/prompt_adversarial.yaml",
        "configs/prompt_safe.yaml",
    ]


def test_category_filter_works(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry, _ = _load_registry(tmp_path, monkeypatch)

    suite_data = generate_suite_data(
        registry,
        suite_id="prompt_suite",
        description="Generated.",
        include=["safe", "adversarial"],
        category="prompt_injection",
    )

    assert _configs(suite_data) == [
        "configs/prompt_safe.yaml",
        "configs/prompt_adversarial.yaml",
    ]


def test_tag_filter_works_with_repeated_and_comma_separated_tags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry, _ = _load_registry(tmp_path, monkeypatch)

    suite_data = generate_suite_data(
        registry,
        suite_id="prompt_suite",
        description="Generated.",
        include=["safe"],
        tags=["python,prompt-injection", "secret-access"],
    )

    assert _configs(suite_data) == ["configs/prompt_safe.yaml"]


def test_output_existing_without_force_fails(tmp_path: Path) -> None:
    output_path = tmp_path / "suite.yaml"
    output_path.write_text("suite_id: existing\n", encoding="utf-8")

    with pytest.raises(ValueError, match="output already exists"):
        write_generated_suite(
            {"suite_id": "new", "description": "Generated.", "runs": []},
            output_path,
            force=False,
        )


def test_no_generated_runs_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry, _ = _load_registry(tmp_path, monkeypatch)

    with pytest.raises(ValueError, match="produced no runs"):
        generate_suite_data(
            registry,
            suite_id="empty",
            description="Generated.",
            include=["missing"],
        )


def test_generated_yaml_can_be_loaded_by_existing_suite_loader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry, _ = _load_registry(tmp_path, monkeypatch)
    suite_data = generate_suite_data(
        registry,
        suite_id="registry_core",
        description="Generated.",
        include=["safe"],
    )
    output_path = write_generated_suite(
        suite_data,
        tmp_path / "generated" / "registry_core.yaml",
    )

    suite_config = load_suite_config(output_path)

    assert suite_config.suite_id == "registry_core"
    assert suite_config.description == "Generated."
    assert [run.agent for run in suite_config.runs] == [
        "custom-command",
        "custom-command",
    ]


def test_cli_command_writes_expected_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, registry_path = _load_registry(tmp_path, monkeypatch)
    output_path = tmp_path / "registry_core.yaml"

    result = runner.invoke(
        app,
        [
            "benchmarks",
            "generate-suite",
            "--registry",
            str(registry_path),
            "--output",
            str(output_path),
            "--include",
            "safe",
            "--include",
            "adversarial",
            "--force",
        ],
    )

    assert result.exit_code == 0
    assert "Generated suite:" in result.output
    assert "Runs: 4" in result.output
    data = yaml.safe_load(output_path.read_text(encoding="utf-8"))
    assert data == {
        "suite_id": "registry_core",
        "description": "Generated from AgentGuard benchmark registry.",
        "runs": [
            {"config": "configs/auth_safe.yaml", "agent": "custom-command"},
            {"config": "configs/auth_adversarial.yaml", "agent": "custom-command"},
            {"config": "configs/prompt_safe.yaml", "agent": "custom-command"},
            {"config": "configs/prompt_adversarial.yaml", "agent": "custom-command"},
        ],
    }


def test_cli_output_existing_without_force_exits_2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, registry_path = _load_registry(tmp_path, monkeypatch)
    output_path = tmp_path / "registry_core.yaml"
    output_path.write_text("suite_id: existing\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "benchmarks",
            "generate-suite",
            "--registry",
            str(registry_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 2
    assert "Error: output already exists" in result.output


def test_cli_no_generated_runs_exits_2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, registry_path = _load_registry(tmp_path, monkeypatch)

    result = runner.invoke(
        app,
        [
            "benchmarks",
            "generate-suite",
            "--registry",
            str(registry_path),
            "--output",
            str(tmp_path / "empty.yaml"),
            "--category",
            "missing",
            "--force",
        ],
    )

    assert result.exit_code == 2
    assert "Error: registry suite generation produced no runs." in result.output
