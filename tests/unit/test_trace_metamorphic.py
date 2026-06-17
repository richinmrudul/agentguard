from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.core.orchestrator import run_benchmark
from agentguard.traces.execution import load_execution_trace, verify_execution_trace
from agentguard.traces.metamorphic import (
    TRANSFORMS,
    parse_transform_selection,
    run_metamorphic_study,
)


runner = CliRunner()


@pytest.fixture(scope="module")
def pass_result():
    return run_benchmark(
        Path("examples/configs/fix_auth_bug.yaml"),
        "mock-safe",
    )


@pytest.fixture(scope="module")
def fail_result():
    return run_benchmark(
        Path("examples/configs/fix_auth_bug.yaml"),
        "mock-test-cheater",
    )


def _trace_path(result) -> Path:
    assert result.report_paths.trace is not None
    return result.report_paths.trace


def test_transform_registry_validation() -> None:
    assert {"preserving", "changing", "invalid"} == {
        definition.transform_class
        for definition, _ in TRANSFORMS.values()
    }
    assert parse_transform_selection(["timestamp_variation,add_test_file"]) == [
        "timestamp_variation",
        "add_test_file",
    ]
    with pytest.raises(ValueError, match="Unsupported"):
        parse_transform_selection(["future"])
    with pytest.raises(ValueError, match="Duplicate"):
        parse_transform_selection(["add_test_file", "add_test_file"])


def test_preserving_transforms_verify_and_keep_outcomes(
    pass_result,
    tmp_path: Path,
) -> None:
    original_bytes = _trace_path(pass_result).read_bytes()
    result = run_metamorphic_study(
        _trace_path(pass_result),
        transform_names=[
            "timestamp_variation",
            "check_message_variation",
            "check_evidence_order",
        ],
        output_dir=tmp_path,
        force=True,
    )

    assert result.metrics.preserving_failed == 0
    assert result.metrics.outcome_stability_rate == 1.0
    assert _trace_path(pass_result).read_bytes() == original_bytes
    for case in result.cases:
        assert case.transformed_trace_path is not None
        assert verify_execution_trace(case.transformed_trace_path).exit_code == 0
        assert case.robustness_passed is True


@pytest.mark.parametrize(
    ("transform", "expected_check"),
    [
        ("add_test_file", "Test tampering"),
        ("add_secret_file", "Secret scan"),
        ("add_unsafe_command", "Unsafe commands"),
        ("increase_diff_size", "Diff size"),
        ("change_test_exit", "Tests passed"),
        ("alter_policy_threshold", "Diff size"),
    ],
)
def test_changing_transforms_trigger_expected_checks(
    pass_result,
    tmp_path: Path,
    transform: str,
    expected_check: str,
) -> None:
    result = run_metamorphic_study(
        _trace_path(pass_result),
        transform_names=[transform],
        output_dir=tmp_path / transform,
        force=True,
    )

    assert result.metrics.changing_failed == 0
    case = result.cases[0]
    assert case.robustness_passed is True
    assert case.transformed_outcome is not None
    assert expected_check in case.transformed_outcome.failed_checks


def test_invalid_transform_is_rejected_and_trace_verification_fails(
    pass_result,
    tmp_path: Path,
) -> None:
    result = run_metamorphic_study(
        _trace_path(pass_result),
        transform_names=["invalid_duplicate_sequence"],
        output_dir=tmp_path,
        force=True,
    )

    case = result.cases[0]
    assert case.robustness_passed is True
    assert result.metrics.invalid_rejected == 1
    assert case.transformed_trace_path is not None
    assert verify_execution_trace(case.transformed_trace_path).exit_code == 2


def test_directory_input_multiple_trials_and_deterministic_order(
    pass_result,
    fail_result,
    tmp_path: Path,
) -> None:
    traces = tmp_path / "traces"
    (traces / "a").mkdir(parents=True)
    (traces / "b").mkdir()
    (traces / "a" / "trace.jsonl").write_bytes(_trace_path(pass_result).read_bytes())
    (traces / "b" / "trace.jsonl").write_bytes(_trace_path(fail_result).read_bytes())

    result = run_metamorphic_study(
        traces,
        transform_names=["timestamp_variation", "add_test_file"],
        trials=2,
        output_dir=tmp_path / "out",
        force=True,
    )

    assert result.metrics.traces_tested == 2
    assert result.metrics.transformations_applied == 8
    assert [case.transform_name for case in result.cases[:2]] == [
        "timestamp_variation",
        "timestamp_variation",
    ]


def test_reports_cli_exit_codes_and_allow_failures(
    pass_result,
    tmp_path: Path,
) -> None:
    report = run_metamorphic_study(
        _trace_path(pass_result),
        transform_names=["add_test_file"],
        output_dir=tmp_path / "reports",
        force=True,
    )
    assert report.report_paths.json.is_file()
    assert report.report_paths.markdown.is_file()
    assert "Metamorphic Trace Study" in report.report_paths.markdown.read_text(
        encoding="utf-8"
    )

    bad = runner.invoke(
        app,
        ["trace", "metamorphic", str(_trace_path(pass_result)), "--transform", "future"],
    )
    ok = runner.invoke(
        app,
        [
            "trace",
            "metamorphic",
            str(_trace_path(pass_result)),
            "--transform",
            "timestamp_variation",
            "--output-dir",
            str(tmp_path / "cli-ok"),
        ],
    )
    allowed = runner.invoke(
        app,
        [
            "trace",
            "metamorphic",
            str(_trace_path(pass_result)),
            "--transform",
            "invalid_duplicate_sequence",
            "--output-dir",
            str(tmp_path / "cli-allowed"),
            "--allow-robustness-failures",
        ],
    )

    assert bad.exit_code == 2
    assert ok.exit_code == 0
    assert allowed.exit_code == 0


def test_no_external_execution_during_metamorphic_study(
    pass_result,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args, **kwargs):
        raise AssertionError("external execution attempted")

    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("socket.socket", forbidden)
    monkeypatch.setattr(
        "agentguard.instrumentation.test_runner.TestRunner.run",
        forbidden,
    )
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.DockerTestRunner.run",
        forbidden,
    )

    result = run_metamorphic_study(
        _trace_path(pass_result),
        transform_names=["timestamp_variation", "add_unsafe_command"],
        output_dir=tmp_path,
        force=True,
    )

    assert result.no_external_execution is True


def test_transformed_trace_digest_changes(pass_result, tmp_path: Path) -> None:
    result = run_metamorphic_study(
        _trace_path(pass_result),
        transform_names=["add_test_file"],
        output_dir=tmp_path,
        force=True,
    )
    source = load_execution_trace(_trace_path(pass_result))
    case = result.cases[0]

    assert case.transformed_trace_id != source.header.trace_id
    assert case.transformed_root_hash != source.header.integrity.root_hash
