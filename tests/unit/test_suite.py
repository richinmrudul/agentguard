import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import agentguard.cli.main as cli_main
from agentguard.cli.main import app
from agentguard.core.suite import run_suite
from agentguard.guard.filesystem import DEFAULT_POLL_INTERVAL_SECONDS, GuardMode


ROOT = Path(__file__).resolve().parents[2]
runner = CliRunner()


def _suite(tmp_path: Path) -> Path:
    path = tmp_path / "suite.yaml"
    config = ROOT / "examples/configs/fix_auth_bug.yaml"
    path.write_text(
        "suite_id: guard_suite\n"
        "description: Guard batch fixture.\n"
        "runs:\n"
        f"  - config: {config}\n"
        "    agent: mock-safe\n",
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize("interval", [0, -1, float("nan"), float("inf")])
def test_suite_api_rejects_invalid_guard_interval(
    tmp_path: Path,
    interval: float,
) -> None:
    with pytest.raises(ValueError, match="finite positive"):
        run_suite(
            _suite(tmp_path),
            suites_root=tmp_path / "out",
            guard_poll_interval_seconds=interval,
        )


def test_suite_reports_manifest_and_child_receive_guard_settings(
    tmp_path: Path,
) -> None:
    result = run_suite(
        _suite(tmp_path),
        suites_root=tmp_path / "out",
        guard_mode=GuardMode.AUDIT,
        guard_poll_interval_seconds=0.05,
    )

    report = json.loads(result.json_report_path.read_text(encoding="utf-8"))
    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    markdown = result.markdown_report_path.read_text(encoding="utf-8")
    child = json.loads(result.runs[0].json_report_path.read_text(encoding="utf-8"))
    assert result.guard_mode == "audit"
    assert result.guard_poll_interval_seconds == 0.05
    assert report["guard_mode"] == "audit"
    assert report["guard_poll_interval_seconds"] == 0.05
    assert "Guard mode: audit" in markdown
    assert "Guard poll interval: 0.05 seconds" in markdown
    assert manifest["guard"] == {
        "guard_mode": "audit",
        "guard_poll_interval_seconds": 0.05,
    }
    assert child["guard_summary"]["mode"] == "audit"
    assert result.passed == 1


def test_suite_cli_defaults_and_forwards_guard_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    def invoke_suite(path: Path, **kwargs):
        calls.append(kwargs)
        return run_suite(path, suites_root=tmp_path / f"out-{len(calls)}", **kwargs)

    monkeypatch.setattr(cli_main, "run_suite", invoke_suite)
    default = runner.invoke(app, ["suite", str(_suite(tmp_path))])
    custom = runner.invoke(
        app,
        [
            "suite",
            str(_suite(tmp_path)),
            "--guard-mode",
            "enforce",
            "--guard-poll-interval",
            "0.05",
        ],
    )

    assert default.exit_code == 0
    assert custom.exit_code == 0
    assert calls[0]["guard_mode"] == GuardMode.OFF
    assert calls[0]["guard_poll_interval_seconds"] == DEFAULT_POLL_INTERVAL_SECONDS
    assert calls[1]["guard_mode"] == GuardMode.ENFORCE
    assert calls[1]["guard_poll_interval_seconds"] == 0.05
    assert "Guard mode: off" in default.output
    assert "Guard poll interval: 0.2 seconds" in default.output
    assert "Guard mode: enforce" in custom.output


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf"])
def test_suite_cli_rejects_invalid_guard_interval(
    tmp_path: Path,
    value: str,
) -> None:
    result = runner.invoke(
        app,
        [
            "suite",
            str(_suite(tmp_path)),
            "--guard-poll-interval",
            value,
        ],
    )
    assert result.exit_code == 2
    assert "finite positive" in result.output
