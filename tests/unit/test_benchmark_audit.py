import json
from pathlib import Path
from typing import Optional

from typer.testing import CliRunner

from agentguard.benchmarks.audit import (
    BenchmarkAuditResult,
    ContractViolation,
    CorpusMetrics,
    evaluate_contract_result,
    run_benchmark_audit,
)
from agentguard.benchmarks.contracts import load_benchmark_contract
from agentguard.cli.main import app
from agentguard.config.loader import load_config
from agentguard.config.schema import BenchmarkMetadata
from agentguard.core.result import (
    BenchmarkResult,
    CheckResult,
    CommandResult,
    DiffSummary,
    ReportPaths,
)


runner = CliRunner()


AUTH_CONTRACT = Path("examples/benchmarks/contracts/auth_bug.yaml")
AUTH_SAFE = Path("examples/configs/fix_auth_bug_docker_command_safe.yaml")
AUTH_CHEATER = Path("examples/configs/fix_auth_bug_docker_command_cheater.yaml")


def _result(
    config_path: Path,
    *,
    result: str = "PASS",
    score: int = 100,
    test_exit_code: int = 0,
    changed: Optional[list[str]] = None,
    failed_checks: Optional[list[str]] = None,
    report_root: Path = Path("/tmp/agentguard-audit-test"),
) -> BenchmarkResult:
    config = load_config(config_path)
    failed = set(failed_checks or [])
    checks = []
    for name in [
        "Tests passed",
        "Forbidden paths",
        "Test tampering",
        "Unsafe commands",
        "Scope adherence",
        "Diff size",
        "Secret scan",
    ]:
        passed = name not in failed
        checks.append(
            CheckResult(
                name=name,
                passed=passed,
                severity="warning" if name in {"Scope adherence", "Diff size"} else "error",
                message=f"{name} {'passed' if passed else 'failed'}",
                evidence=list(changed or []),
            )
        )
    return BenchmarkResult(
        task_id=config.task_id,
        agent="custom-command",
        result=result,
        score=score,
        config_path=config.config_path,
        run_dir=report_root / "run",
        repo_dir=report_root / "repo",
        test_result=CommandResult(
            command=config.test_command,
            exit_code=test_exit_code,
            stdout="",
            stderr="",
            duration_seconds=0.0,
        ),
        diff_summary=DiffSummary(
            modified_files=changed or [],
            added_files=[],
            deleted_files=[],
            lines_added=1,
            lines_deleted=1,
            unified_diff="",
        ),
        check_results=checks,
        report_paths=ReportPaths(
            json=report_root / "report.json",
            markdown=report_root / "report.md",
            manifest=report_root / "manifest.json",
        ),
        benchmark=BenchmarkMetadata(
            id=config.benchmark.id,
            version=config.benchmark.version,
            category=config.benchmark.category,
            difficulty=config.benchmark.difficulty,
            tags=config.benchmark.tags,
        ),
    )


def _auth_variant(name: str):
    contract = load_benchmark_contract(AUTH_CONTRACT)
    return next(variant for variant in contract.variants if variant.name == name)


def test_safe_result_satisfies_safe_contract() -> None:
    trial = evaluate_contract_result(
        "auth_bug",
        _auth_variant("safe"),
        1,
        _result(AUTH_SAFE, changed=["src/auth_example/login.py"]),
    )

    assert trial.contract_passed
    assert trial.violations == []


def test_adversarial_result_satisfies_adversarial_contract() -> None:
    trial = evaluate_contract_result(
        "auth_bug",
        _auth_variant("adversarial"),
        1,
        _result(
            AUTH_CHEATER,
            result="FAIL",
            score=60,
            changed=["tests/test_auth.py"],
            failed_checks=["Test tampering", "Scope adherence"],
        ),
    )

    assert trial.contract_passed
    assert trial.functional_tests == "PASS"


def test_missing_required_check_and_path_fail() -> None:
    trial = evaluate_contract_result(
        "auth_bug",
        _auth_variant("adversarial"),
        1,
        _result(
            AUTH_CHEATER,
            result="FAIL",
            score=60,
            changed=[],
            failed_checks=["Test tampering"],
        ),
    )

    fields = {violation.field for violation in trial.violations}
    assert "modified_paths.required" in fields
    assert "failed_checks.required" in fields
    assert not trial.contract_passed


def test_result_score_functional_and_forbidden_mismatches_fail() -> None:
    trial = evaluate_contract_result(
        "auth_bug",
        _auth_variant("safe"),
        1,
        _result(
            AUTH_SAFE,
            result="FAIL",
            score=90,
            test_exit_code=1,
            changed=["tests/test_auth.py"],
            failed_checks=["Test tampering"],
        ),
    )

    fields = {violation.field for violation in trial.violations}
    assert {
        "result",
        "functional_tests",
        "score",
        "modified_paths.forbidden",
        "failed_checks.forbidden",
    } <= fields


def test_unexpected_check_warns_by_default_and_fails_in_strict_mode() -> None:
    result = _result(
        AUTH_SAFE,
        changed=["src/auth_example/login.py"],
        failed_checks=["Diff size"],
    )

    default = evaluate_contract_result("auth_bug", _auth_variant("safe"), 1, result)
    strict = evaluate_contract_result(
        "auth_bug",
        _auth_variant("safe"),
        1,
        result,
        strict_unexpected_checks=True,
    )

    assert default.contract_passed
    assert default.violations[0].severity == "warning"
    assert not strict.contract_passed
    assert strict.violations[0].severity == "error"


def test_repeated_identical_trials_are_stable_and_write_reports(tmp_path: Path) -> None:
    def benchmark_runner(config_path: Path, agent: str) -> BenchmarkResult:
        assert agent == "custom-command"
        if config_path == AUTH_CHEATER:
            return _result(
                config_path,
                result="FAIL",
                score=60,
                changed=["tests/test_auth.py"],
                failed_checks=["Test tampering", "Scope adherence"],
                report_root=tmp_path,
            )
        return _result(
            config_path,
            changed=["src/auth_example/login.py"],
            report_root=tmp_path,
        )

    result = run_benchmark_audit(
        benchmark_ids=["auth_bug"],
        trials=3,
        workers=2,
        output_dir=tmp_path / "audits",
        benchmark_runner=benchmark_runner,
    )

    assert result.total_trials == 6
    assert result.unstable_variants == 0
    assert result.failed_contracts == 0
    assert result.json_report_path.exists()
    assert result.markdown_report_path.exists()
    data = json.loads(result.json_report_path.read_text(encoding="utf-8"))
    assert data["schema"] == "agentguard.benchmark-audit"


def test_disagreeing_trials_mark_variant_unstable(tmp_path: Path) -> None:
    calls = 0

    def benchmark_runner(config_path: Path, agent: str) -> BenchmarkResult:
        nonlocal calls
        calls += 1
        changed = ["src/auth_example/login.py"] if calls % 2 else ["tests/test_auth.py"]
        return _result(config_path, changed=changed, report_root=tmp_path)

    result = run_benchmark_audit(
        benchmark_ids=["auth_bug"],
        trials=2,
        output_dir=tmp_path / "audits",
        benchmark_runner=benchmark_runner,
    )

    assert result.unstable_variants >= 1
    assert result.has_failures


def test_runtime_error_becomes_contract_violation(tmp_path: Path) -> None:
    def benchmark_runner(config_path: Path, agent: str) -> BenchmarkResult:
        raise RuntimeError("boom")

    result = run_benchmark_audit(
        benchmark_ids=["auth_bug"],
        output_dir=tmp_path / "audits",
        benchmark_runner=benchmark_runner,
    )

    assert result.error_count == 2
    assert {violation.field for violation in result.violations} == {"runtime"}


def test_static_audit_executes_nothing_and_reports_coverage(tmp_path: Path) -> None:
    def benchmark_runner(config_path: Path, agent: str) -> BenchmarkResult:
        raise AssertionError("static audit should not execute")

    result = run_benchmark_audit(
        static_only=True,
        output_dir=tmp_path / "audits",
        benchmark_runner=benchmark_runner,
    )

    assert result.mode == "static"
    assert result.total_benchmarks == 9
    assert result.total_variants == 18
    assert result.corpus_metrics.contract_coverage_percentage == 100.0


def test_filters_apply_before_execution(tmp_path: Path) -> None:
    result = run_benchmark_audit(
        static_only=True,
        benchmark_ids=["auth_bug,cli_parser_bug"],
        category="test_tampering",
        output_dir=tmp_path / "audits",
    )

    assert result.selected_benchmarks == ["auth_bug", "cli_parser_bug"]


def test_cli_exit_codes_for_static_and_allowed_failures(tmp_path: Path) -> None:
    static_result = runner.invoke(
        app,
        [
            "benchmarks",
            "audit",
            "--static-only",
            "--output-dir",
            str(tmp_path / "static"),
        ],
    )
    invalid_result = runner.invoke(app, ["benchmarks", "audit", "--trials", "0"])

    assert static_result.exit_code == 0
    assert "AgentGuard Benchmark Audit" in static_result.output
    assert invalid_result.exit_code == 2
    assert "trials must be a positive integer" in invalid_result.output


def test_cli_allow_contract_failures_exits_zero(
    tmp_path: Path,
    monkeypatch,
) -> None:
    violation = ContractViolation(
        benchmark_id="auth_bug",
        variant="safe",
        trial_index=1,
        field="result",
        expected="PASS",
        actual="FAIL",
        message="mock violation",
        severity="error",
    )

    def fake_audit(*args, **kwargs) -> BenchmarkAuditResult:
        return BenchmarkAuditResult(
            audit_id="mock-audit",
            schema="agentguard.benchmark-audit",
            schema_version=1,
            mode="execution",
            selected_benchmarks=["auth_bug"],
            trials=1,
            workers=1,
            total_benchmarks=1,
            total_variants=1,
            total_trials=1,
            passed_contracts=0,
            failed_contracts=1,
            unstable_variants=0,
            warning_count=0,
            error_count=1,
            variants=[],
            violations=[violation],
            corpus_metrics=CorpusMetrics(
                registry_benchmarks=1,
                contracts=1,
                contract_coverage_percentage=100.0,
                safe_variants=1,
                adversarial_variants=0,
                categories=["test_tampering"],
                difficulties=["easy"],
                required_check_frequency={},
                evidence_pattern_variants=0,
                evidence_pattern_coverage_percentage=0.0,
            ),
            duration_seconds=0.0,
            json_report_path=tmp_path / "audit.json",
            markdown_report_path=tmp_path / "audit.md",
        )

    monkeypatch.setattr("agentguard.cli.main.run_benchmark_audit", fake_audit)

    blocked = runner.invoke(app, ["benchmarks", "audit"])
    allowed = runner.invoke(
        app,
        ["benchmarks", "audit", "--allow-contract-failures"],
    )

    assert blocked.exit_code == 1
    assert allowed.exit_code == 0
    assert "mock violation" in allowed.output
