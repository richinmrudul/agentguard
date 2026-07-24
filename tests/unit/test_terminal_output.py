import csv
from io import StringIO
from pathlib import Path

from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.evaluation.harness import (
    EvaluationPlan,
    EvaluationPlanRun,
    format_evaluation_plan,
)
from agentguard.evaluation.profile import (
    AgentProfile,
    RenderedInvocation,
    TaskPrompt,
)
from agentguard.history.store import HistoryRecord, export_history_csv
from agentguard.terminal import sanitize_terminal_text


CONTROL_TEXT = "safe\x1b]0;CANARY\x07\x1b[31m\r\b\x7f\x85text"


def test_terminal_sanitizer_neutralizes_controls_and_preserves_unicode() -> None:
    rendered = sanitize_terminal_text(CONTROL_TEXT + " café 日本語")

    assert rendered == (
        "safe\\x1b]0;CANARY\\x07\\x1b[31m\\x0d\\x08\\x7f\\x85text"
        " café 日本語"
    )
    assert not any(
        ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F
        for character in rendered
    )


def test_cli_report_show_does_not_emit_raw_control_bytes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    report = tmp_path / "report.json"
    report.write_text(
        '{"task_id": "safe\\u001b]0;CANARY\\u0007task", '
        '"agent": "mock", "result": "PASS", "score": 100}',
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["reports", "show", str(report)])

    assert result.exit_code == 0
    assert "\x1b" not in result.output
    assert "\x07" not in result.output
    assert "safe\\x1b]0;CANARY\\x07task" in result.output


def test_evaluation_plan_neutralizes_profile_and_run_controls() -> None:
    prompt = TaskPrompt(text="", source="inline", sha256="0" * 64)
    invocation = RenderedInvocation(
        argv=["agent"],
        display_argv=["agent", CONTROL_TEXT],
        workdir=Path("/tmp/work"),
        environment={},
        task_prompt=prompt,
    )
    plan = EvaluationPlan(
        profile=AgentProfile(
            id=CONTROL_TEXT,
            name="Café",
            command=["agent"],
            profile_path=Path("profile.yaml"),
        ),
        suite_path=Path("suite.yaml"),
        suite_id=CONTROL_TEXT,
        runs=[
            EvaluationPlanRun(
                config_path=Path("config.yaml"),
                task_id=CONTROL_TEXT,
                benchmark_id=None,
                benchmark_version=None,
                prompt_source="inline",
                prompt_sha256="0" * 64,
                invocation=invocation,
            )
        ],
        trials=1,
        workers=1,
        total_attempts=1,
    )

    rendered = format_evaluation_plan(plan)

    assert "\x1b" not in rendered
    assert "\x07" not in rendered
    assert "\\x1b]0;CANARY\\x07" in rendered
    assert "Café" in rendered


def test_history_csv_neutralizes_field_controls_and_keeps_csv_framing() -> None:
    content = export_history_csv(
        [
            HistoryRecord(
                id="run",
                run_type="run",
                name=CONTROL_TEXT,
                result="PASS",
                score=100,
                created_at="2026-07-24T00:00:00+00:00",
                json_report_path=Path("report.json"),
            )
        ]
    )

    row = next(csv.DictReader(StringIO(content)))

    assert content.endswith("\r\n")
    assert "\x1b" not in content
    assert "\x07" not in content
    assert row["name"] == (
        "safe\\x1b]0;CANARY\\x07\\x1b[31m\\x0d\\x08\\x7f\\x85text"
    )
