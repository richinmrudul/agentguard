import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.core.matrix import run_matrix
from agentguard.core.matrix_checkpoint import load_checkpoint
from agentguard.history.store import list_history


runner = CliRunner()
REPO_ROOT = Path(__file__).resolve().parents[2]


def _suite(tmp_path: Path, agent: str = "mock-safe") -> Path:
    config = REPO_ROOT / "examples/configs/fix_auth_bug.yaml"
    path = tmp_path / "resume-suite.yaml"
    path.write_text(
        "suite_id: resume_suite\n"
        "description: Resume integration fixture.\n"
        "runs:\n"
        f"  - config: {config}\n"
        f"    agent: {agent}\n",
        encoding="utf-8",
    )
    return path


def test_interrupted_matrix_resumes_verified_attempts_with_workers(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    suite = _suite(tmp_path)
    checkpoint = tmp_path / "checkpoint.json"
    output = tmp_path / "matrices"

    with pytest.raises(KeyboardInterrupt):
        run_matrix(
            suite,
            trials=4,
            workers=2,
            matrices_root=output,
            checkpoint_path=checkpoint,
            _interrupt_after_attempts=2,
        )

    interrupted = load_checkpoint(checkpoint)
    assert interrupted.status == "interrupted"
    assert all(
        attempt.status in {"pending", "completed"}
        for attempt in interrupted.attempts
    )
    completed = sum(
        attempt.status == "completed" for attempt in interrupted.attempts
    )
    assert completed >= 2

    resumed = run_matrix(
        suite,
        trials=4,
        workers=2,
        matrices_root=output,
        resume_path=checkpoint,
    )

    assert resumed.attempts_reused == completed
    assert resumed.attempts_skipped == completed
    assert resumed.attempts_executed_this_invocation == 4 - completed
    assert [row.trial_index for row in resumed.runs] == [1, 2, 3, 4]
    assert resumed.reliability is not None
    assert resumed.reliability.attempts == 4
    assert load_checkpoint(checkpoint).status == "completed"
    records = list_history(tmp_path / ".agentguard/history.db", limit=None)
    run_ids = [record.id for record in records if record.run_type == "run"]
    assert len(run_ids) == 4
    assert len(run_ids) == len(set(run_ids))


def test_completed_failures_are_reused_or_retried(tmp_path: Path) -> None:
    suite = _suite(tmp_path, "mock-test-cheater")
    checkpoint = tmp_path / "failure-checkpoint.json"
    first = run_matrix(
        suite,
        matrices_root=tmp_path / "matrices",
        checkpoint_path=checkpoint,
    )
    assert first.failed == 1

    reused = run_matrix(
        suite,
        matrices_root=tmp_path / "matrices",
        resume_path=checkpoint,
    )
    assert reused.attempts_reused == 1
    assert reused.attempts_executed_this_invocation == 0

    retried = run_matrix(
        suite,
        matrices_root=tmp_path / "matrices",
        resume_path=checkpoint,
        retry_failed=True,
    )
    assert retried.attempts_reused == 0
    assert retried.failed_attempts_retried == 1
    assert retried.attempts_executed_this_invocation == 1


def test_resume_refuses_corrupted_artifact_even_with_force(tmp_path: Path) -> None:
    suite = _suite(tmp_path)
    checkpoint = tmp_path / "corrupt-checkpoint.json"
    run_matrix(
        suite,
        matrices_root=tmp_path / "matrices",
        checkpoint_path=checkpoint,
    )
    stored = load_checkpoint(checkpoint)
    report = Path(stored.attempts[0].json_report_path or "")
    report.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="corrupted.*Hash mismatch"):
        run_matrix(
            suite,
            matrices_root=tmp_path / "matrices",
            resume_path=checkpoint,
            force_resume=True,
        )


def test_resume_rejects_changed_suite_and_cli_combinations(tmp_path: Path) -> None:
    suite = _suite(tmp_path)
    checkpoint = tmp_path / "checkpoint.json"
    run_matrix(
        suite,
        matrices_root=tmp_path / "matrices",
        checkpoint_path=checkpoint,
    )
    suite.write_text(
        suite.read_text(encoding="utf-8") + "\n# changed\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["matrix", str(suite), "--resume", str(checkpoint)],
    )
    assert result.exit_code == 2
    assert "incompatible" in result.output

    invalid = runner.invoke(
        app,
        [
            "matrix",
            str(suite),
            "--checkpoint",
            str(tmp_path / "new.json"),
            "--resume",
            str(checkpoint),
        ],
    )
    assert invalid.exit_code == 2

    invalid_interval = runner.invoke(
        app,
        ["matrix", str(suite), "--checkpoint-every", "0"],
    )
    assert invalid_interval.exit_code == 2

    retry_without_resume = runner.invoke(
        app,
        ["matrix", str(suite), "--retry-failed"],
    )
    assert retry_without_resume.exit_code == 2


def test_checkpoint_lineage_is_written_to_reports_and_manifest(
    tmp_path: Path,
) -> None:
    suite = _suite(tmp_path)
    checkpoint = tmp_path / "checkpoint.json"
    first = run_matrix(
        suite,
        matrices_root=tmp_path / "matrices",
        checkpoint_path=checkpoint,
    )
    resumed = run_matrix(
        suite,
        matrices_root=tmp_path / "matrices",
        resume_path=checkpoint,
        save_reliability_baseline_path=tmp_path / "reliability.json",
    )

    report = json.loads(resumed.json_report_path.read_text(encoding="utf-8"))
    manifest = json.loads(resumed.manifest_path.read_text(encoding="utf-8"))
    markdown = resumed.markdown_report_path.read_text(encoding="utf-8")
    assert report["attempts_reused"] == 1
    assert report["attempts_skipped"] == 1
    assert report["checkpoint_id"] == first.checkpoint_id
    assert manifest["matrix"]["attempts_reused"] == 1
    assert manifest["matrix"]["attempts_skipped"] == 1
    assert "## Checkpoint and Resume" in markdown
    assert resumed.result_counts == first.result_counts
    assert resumed.reliability == first.reliability
    assert (tmp_path / "reliability.json").is_file()


def test_fail_fast_resume_does_not_schedule_past_reused_failure(
    tmp_path: Path,
) -> None:
    suite = _suite(tmp_path, "mock-test-cheater")
    checkpoint = tmp_path / "fail-fast-checkpoint.json"
    first = run_matrix(
        suite,
        trials=4,
        workers=1,
        fail_fast=True,
        matrices_root=tmp_path / "matrices",
        checkpoint_path=checkpoint,
    )
    assert first.attempts_executed == 1
    assert first.stopped_early

    resumed = run_matrix(
        suite,
        trials=4,
        workers=2,
        fail_fast=True,
        matrices_root=tmp_path / "matrices",
        resume_path=checkpoint,
    )

    assert resumed.attempts_reused == 1
    assert resumed.attempts_executed_this_invocation == 0
    assert resumed.attempts_executed == 1
    assert resumed.stopped_early
