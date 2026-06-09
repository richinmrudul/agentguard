import json
from pathlib import Path

from agentguard.diagnostics.overhead import run_overhead_benchmark


def test_real_non_docker_overhead_benchmark(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    config_path = repo_root / "examples/configs/fix_auth_bug.yaml"
    monkeypatch.chdir(tmp_path)

    result = run_overhead_benchmark(
        config_path,
        "mock-safe",
        iterations=1,
        warmups=0,
        output_path=tmp_path / "overhead.json",
    )

    data = json.loads(result.paths.json.read_text(encoding="utf-8"))
    assert data["raw_timings"][0]["functional_outcome"]["test_exit_code"] == 0
    assert data["raw_timings"][0]["functional_outcome"]["changed_files"] == [
        "src/auth_example/login.py"
    ]
    assert data["summary"]["direct_seconds"]["median"] > 0
    assert data["summary"]["agentguard_seconds"]["median"] > 0
    assert data["agentguard_stage_summary"]["policy_check_evaluation"][
        "mean_seconds"
    ] > 0
    assert result.paths.markdown.is_file()
    assert list((tmp_path / ".agentguard/runs").glob("*/manifest.json"))


def test_real_overhead_benchmark_can_disable_history_and_manifest(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    config_path = repo_root / "examples/configs/fix_auth_bug.yaml"
    monkeypatch.chdir(tmp_path)

    result = run_overhead_benchmark(
        config_path,
        "mock-safe",
        iterations=1,
        warmups=0,
        output_path=tmp_path / "overhead.json",
        record_history_enabled=False,
        write_manifest_enabled=False,
    )

    data = result.data
    assert data["methodology"]["history_included"] is False
    assert data["methodology"]["manifest_included"] is False
    assert not (tmp_path / ".agentguard/history.db").exists()
    assert not list((tmp_path / ".agentguard/runs").glob("*/manifest.json"))
