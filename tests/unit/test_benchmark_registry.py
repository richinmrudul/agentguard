from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from agentguard.benchmarks.registry import find_benchmark, load_benchmark_registry
from agentguard.cli.main import app


runner = CliRunner()


def _write_registry(tmp_path: Path, body: str) -> Path:
    registry_path = tmp_path / "registry.yaml"
    registry_path.write_text(body, encoding="utf-8")
    return registry_path


def _write_valid_registry(tmp_path: Path) -> Path:
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    (config_dir / "safe.yaml").write_text("task_id: safe\n", encoding="utf-8")
    (config_dir / "cheater.yaml").write_text("task_id: cheater\n", encoding="utf-8")
    contract_dir = tmp_path / "contracts"
    contract_dir.mkdir()
    (contract_dir / "auth_bug.yaml").write_text("{}\n", encoding="utf-8")
    return _write_registry(
        tmp_path,
        """
benchmarks:
  - id: auth_bug
    version: 1
    name: Auth Login Bug
    category: test_tampering
    difficulty: easy
    description: Detects source fixes versus test tampering.
    tags:
      - python
      - docker
    configs:
      safe: configs/safe.yaml
      adversarial: configs/cheater.yaml
    contract: contracts/auth_bug.yaml
""",
    )


def test_loads_valid_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    registry_path = _write_valid_registry(tmp_path)
    monkeypatch.chdir(tmp_path)

    registry = load_benchmark_registry(registry_path)

    assert registry.path == registry_path
    assert len(registry.benchmarks) == 1
    assert registry.benchmarks[0].id == "auth_bug"
    assert registry.benchmarks[0].configs["safe"] == Path("configs/safe.yaml")


def test_rejects_missing_top_level_benchmarks(tmp_path: Path) -> None:
    registry_path = _write_registry(tmp_path, "not_benchmarks: []\n")

    with pytest.raises(ValueError, match="field 'benchmarks' must be a list"):
        load_benchmark_registry(registry_path)


def test_rejects_duplicate_ids(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    (config_dir / "safe.yaml").write_text("task_id: safe\n", encoding="utf-8")
    contract_dir = tmp_path / "contracts"
    contract_dir.mkdir()
    (contract_dir / "auth_bug.yaml").write_text("{}\n", encoding="utf-8")
    registry_path = _write_registry(
        tmp_path,
        """
benchmarks:
  - id: auth_bug
    version: 1
    name: Auth Login Bug
    category: test_tampering
    difficulty: easy
    description: First.
    tags:
      - python
    configs:
      safe: configs/safe.yaml
    contract: contracts/auth_bug.yaml
  - id: auth_bug
    version: 1
    name: Auth Login Bug Copy
    category: test_tampering
    difficulty: easy
    description: Duplicate.
    tags:
      - python
    configs:
      safe: configs/safe.yaml
    contract: contracts/auth_bug.yaml
""",
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError, match="Duplicate benchmark id"):
        load_benchmark_registry(registry_path)


def test_rejects_invalid_difficulty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry_path = _write_valid_registry(tmp_path)
    registry_path.write_text(
        registry_path.read_text(encoding="utf-8").replace(
            "difficulty: easy",
            "difficulty: impossible",
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError, match="field 'difficulty' must be one of"):
        load_benchmark_registry(registry_path)


def test_rejects_non_positive_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry_path = _write_valid_registry(tmp_path)
    registry_path.write_text(
        registry_path.read_text(encoding="utf-8").replace("version: 1", "version: 0"),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError, match="field 'version' must be a positive integer"):
        load_benchmark_registry(registry_path)


def test_find_benchmark_works(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry_path = _write_valid_registry(tmp_path)
    monkeypatch.chdir(tmp_path)
    registry = load_benchmark_registry(registry_path)

    assert find_benchmark(registry, "auth_bug") is registry.benchmarks[0]
    assert find_benchmark(registry, "missing") is None


def test_list_output_includes_benchmark_ids(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry_path = _write_valid_registry(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["benchmarks", "list", "--registry", str(registry_path)])

    assert result.exit_code == 0
    assert "Registered AgentGuard Benchmarks" in result.output
    assert "auth_bug | 1 | test_tampering | easy" in result.output


def test_show_output_includes_configs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry_path = _write_valid_registry(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        ["benchmarks", "show", "auth_bug", "--registry", str(registry_path)],
    )

    assert result.exit_code == 0
    assert "ID: auth_bug" in result.output
    assert "Configs:" in result.output
    assert "- safe: configs/safe.yaml" in result.output
    assert "- adversarial: configs/cheater.yaml" in result.output


def test_show_missing_id_exits_2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry_path = _write_valid_registry(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        ["benchmarks", "show", "missing", "--registry", str(registry_path)],
    )

    assert result.exit_code == 2
    assert "Error: benchmark not found: missing" in result.output


def test_registry_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    registry_path = _write_registry(
        tmp_path,
        "schema_version: 1\n"
        "benchmarks: []\n"
        "benchmarks: []\n",
    )

    with pytest.raises(yaml.YAMLError, match="duplicate key 'benchmarks'"):
        load_benchmark_registry(registry_path)
