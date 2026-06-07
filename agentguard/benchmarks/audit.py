import json
import time
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Callable, Optional
from uuid import uuid4

from agentguard.benchmarks.contracts import (
    BenchmarkContract,
    ContractVariant,
    load_registry_contracts,
)
from agentguard.benchmarks.registry import (
    DEFAULT_REGISTRY_PATH,
    BenchmarkRegistryEntry,
    load_benchmark_registry,
    normalize_registry_values,
)
from agentguard.core.orchestrator import run_benchmark
from agentguard.core.result import BenchmarkResult
from agentguard.policy.path_matcher import matches_path


AUDIT_SCHEMA = "agentguard.benchmark-audit"
AUDIT_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ContractViolation:
    benchmark_id: str
    variant: str
    trial_index: int
    field: str
    expected: Any
    actual: Any
    message: str
    severity: str


@dataclass(frozen=True)
class ContractTrialResult:
    benchmark_id: str
    variant: str
    trial_index: int
    contract_passed: bool
    result: str
    functional_tests: str
    score: int
    failed_checks: list[str]
    modified_paths: list[str]
    violations: list[ContractViolation]
    report_path: Optional[Path] = None
    manifest_path: Optional[Path] = None
    runtime_error: Optional[str] = None


@dataclass(frozen=True)
class ContractVariantAudit:
    benchmark_id: str
    variant: str
    config_path: Path
    passed: bool
    unstable: bool
    trials: list[ContractTrialResult]
    violations: list[ContractViolation]
    observed_results: list[str]
    observed_functional_results: list[str]
    observed_scores: list[int]
    observed_failed_check_sets: list[list[str]]
    observed_modified_file_sets: list[list[str]]


@dataclass(frozen=True)
class CorpusMetrics:
    registry_benchmarks: int
    contracts: int
    contract_coverage_percentage: float
    safe_variants: int
    adversarial_variants: int
    categories: list[str]
    difficulties: list[str]
    required_check_frequency: dict[str, int]
    evidence_pattern_variants: int
    evidence_pattern_coverage_percentage: float


@dataclass(frozen=True)
class BenchmarkAuditResult:
    audit_id: str
    schema: str
    schema_version: int
    mode: str
    selected_benchmarks: list[str]
    trials: int
    workers: int
    total_benchmarks: int
    total_variants: int
    total_trials: int
    passed_contracts: int
    failed_contracts: int
    unstable_variants: int
    warning_count: int
    error_count: int
    variants: list[ContractVariantAudit]
    violations: list[ContractViolation]
    corpus_metrics: CorpusMetrics
    duration_seconds: float
    json_report_path: Path
    markdown_report_path: Path
    static_validation: list[str] = field(default_factory=list)

    @property
    def has_failures(self) -> bool:
        return self.error_count > 0 or self.unstable_variants > 0


def _audit_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    return f"benchmark-audit-{timestamp}-{uuid4().hex[:8]}"


def _violation(
    benchmark_id: str,
    variant: str,
    trial_index: int,
    field_name: str,
    expected: Any,
    actual: Any,
    message: str,
    severity: str = "error",
) -> ContractViolation:
    return ContractViolation(
        benchmark_id=benchmark_id,
        variant=variant,
        trial_index=trial_index,
        field=field_name,
        expected=expected,
        actual=actual,
        message=message,
        severity=severity,
    )


def _contains_pattern(values: list[str], pattern: str) -> bool:
    return any(fnmatchcase(value, pattern) for value in values)


def evaluate_contract_result(
    benchmark_id: str,
    variant: ContractVariant,
    trial_index: int,
    result: BenchmarkResult,
    *,
    strict_unexpected_checks: bool = False,
) -> ContractTrialResult:
    expected = variant.expected
    failed_checks = sorted(
        check.name for check in result.check_results if not check.passed
    )
    changed_paths = sorted(result.diff_summary.changed_files)
    functional = "PASS" if result.test_result.exit_code == 0 else "FAIL"
    violations: list[ContractViolation] = []

    comparisons = [
        ("result", expected.result, result.result),
        ("functional_tests", expected.functional_tests, functional),
    ]
    for field_name, wanted, actual in comparisons:
        if wanted != actual:
            violations.append(
                _violation(
                    benchmark_id,
                    variant.name,
                    trial_index,
                    field_name,
                    wanted,
                    actual,
                    f"Expected {field_name} {wanted}, observed {actual}.",
                )
            )
    if not expected.score.min <= result.score <= expected.score.max:
        violations.append(
            _violation(
                benchmark_id,
                variant.name,
                trial_index,
                "score",
                {"min": expected.score.min, "max": expected.score.max},
                result.score,
                "Observed score is outside the contracted range.",
            )
        )

    for pattern in expected.modified_paths.required:
        if not any(matches_path(path, pattern) for path in changed_paths):
            violations.append(
                _violation(
                    benchmark_id,
                    variant.name,
                    trial_index,
                    "modified_paths.required",
                    pattern,
                    changed_paths,
                    f"Required modified path pattern was not observed: {pattern}",
                )
            )
    if expected.modified_paths.allowed:
        outside = [
            path
            for path in changed_paths
            if not any(
                matches_path(path, pattern)
                for pattern in expected.modified_paths.allowed
            )
        ]
        if outside:
            violations.append(
                _violation(
                    benchmark_id,
                    variant.name,
                    trial_index,
                    "modified_paths.allowed",
                    expected.modified_paths.allowed,
                    outside,
                    "Modified paths fell outside the contracted allowlist.",
                )
            )
    for pattern in expected.modified_paths.forbidden:
        matches = [path for path in changed_paths if matches_path(path, pattern)]
        if matches:
            violations.append(
                _violation(
                    benchmark_id,
                    variant.name,
                    trial_index,
                    "modified_paths.forbidden",
                    pattern,
                    matches,
                    f"Forbidden modified path pattern was observed: {pattern}",
                )
            )

    for check_name in expected.failed_checks.required:
        if check_name not in failed_checks:
            violations.append(
                _violation(
                    benchmark_id,
                    variant.name,
                    trial_index,
                    "failed_checks.required",
                    check_name,
                    failed_checks,
                    f"Required failed check was absent: {check_name}",
                )
            )
    for check_name in expected.failed_checks.forbidden:
        if check_name in failed_checks:
            violations.append(
                _violation(
                    benchmark_id,
                    variant.name,
                    trial_index,
                    "failed_checks.forbidden",
                    check_name,
                    failed_checks,
                    f"Forbidden failed check was observed: {check_name}",
                )
            )
    required_checks = set(expected.failed_checks.required)
    forbidden_checks = set(expected.failed_checks.forbidden)
    for check_name in sorted(set(failed_checks) - required_checks):
        if check_name in forbidden_checks:
            continue
        violations.append(
            _violation(
                benchmark_id,
                variant.name,
                trial_index,
                "failed_checks.unexpected",
                sorted(required_checks),
                check_name,
                f"Unexpected failed check was observed: {check_name}",
                "error" if strict_unexpected_checks else "warning",
            )
        )

    evidence = list(changed_paths)
    evidence.extend(failed_checks)
    for check in result.check_results:
        evidence.append(check.message)
        evidence.extend(check.evidence)
    for pattern in expected.evidence_patterns.required:
        if not _contains_pattern(evidence, pattern):
            violations.append(
                _violation(
                    benchmark_id,
                    variant.name,
                    trial_index,
                    "evidence_patterns.required",
                    pattern,
                    evidence,
                    f"Required evidence pattern was not observed: {pattern}",
                )
            )
    for pattern in expected.evidence_patterns.forbidden:
        if _contains_pattern(evidence, pattern):
            violations.append(
                _violation(
                    benchmark_id,
                    variant.name,
                    trial_index,
                    "evidence_patterns.forbidden",
                    pattern,
                    evidence,
                    f"Forbidden evidence pattern was observed: {pattern}",
                )
            )

    return ContractTrialResult(
        benchmark_id=benchmark_id,
        variant=variant.name,
        trial_index=trial_index,
        contract_passed=not any(item.severity == "error" for item in violations),
        result=result.result,
        functional_tests=functional,
        score=result.score,
        failed_checks=failed_checks,
        modified_paths=changed_paths,
        violations=violations,
        report_path=result.report_paths.json,
        manifest_path=result.report_paths.manifest,
    )


def _runtime_failure(
    benchmark_id: str,
    variant: ContractVariant,
    trial_index: int,
    error: Exception,
) -> ContractTrialResult:
    message = f"{type(error).__name__}: {error}"
    violation = _violation(
        benchmark_id,
        variant.name,
        trial_index,
        "runtime",
        "successful benchmark execution",
        message,
        "Benchmark execution failed before a result could be audited.",
    )
    return ContractTrialResult(
        benchmark_id=benchmark_id,
        variant=variant.name,
        trial_index=trial_index,
        contract_passed=False,
        result="FAIL",
        functional_tests="FAIL",
        score=0,
        failed_checks=["Runtime error"],
        modified_paths=[],
        violations=[violation],
        runtime_error=message,
    )


def _variant_audit(
    benchmark_id: str,
    variant: ContractVariant,
    trials: list[ContractTrialResult],
) -> ContractVariantAudit:
    signatures = {
        (
            trial.result,
            trial.functional_tests,
            tuple(trial.failed_checks),
            tuple(trial.modified_paths),
        )
        for trial in trials
    }
    unstable = len(signatures) > 1
    violations = [item for trial in trials for item in trial.violations]
    if unstable:
        violations.append(
            _violation(
                benchmark_id,
                variant.name,
                0,
                "stability",
                "identical trial observations",
                [
                    {
                        "result": trial.result,
                        "functional_tests": trial.functional_tests,
                        "failed_checks": trial.failed_checks,
                        "modified_paths": trial.modified_paths,
                    }
                    for trial in trials
                ],
                "Repeated trials produced different contract observations.",
            )
        )
    return ContractVariantAudit(
        benchmark_id=benchmark_id,
        variant=variant.name,
        config_path=variant.config,
        passed=not any(item.severity == "error" for item in violations),
        unstable=unstable,
        trials=trials,
        violations=violations,
        observed_results=sorted({trial.result for trial in trials}),
        observed_functional_results=sorted(
            {trial.functional_tests for trial in trials}
        ),
        observed_scores=[trial.score for trial in trials],
        observed_failed_check_sets=[
            trial.failed_checks for trial in trials
        ],
        observed_modified_file_sets=[
            trial.modified_paths for trial in trials
        ],
    )


def _corpus_metrics(
    pairs: list[tuple[BenchmarkRegistryEntry, BenchmarkContract]],
    registry_count: int,
) -> CorpusMetrics:
    contracts = len(pairs)
    variants = [
        variant
        for _, contract in pairs
        for variant in contract.variants
    ]
    required_checks = Counter(
        check_name
        for variant in variants
        for check_name in variant.expected.failed_checks.required
    )
    evidence_variants = sum(
        bool(variant.expected.evidence_patterns.required)
        for variant in variants
    )
    return CorpusMetrics(
        registry_benchmarks=registry_count,
        contracts=contracts,
        contract_coverage_percentage=round(
            (contracts / registry_count) * 100 if registry_count else 100.0,
            1,
        ),
        safe_variants=sum(variant.name == "safe" for variant in variants),
        adversarial_variants=sum(
            variant.name == "adversarial" for variant in variants
        ),
        categories=sorted({entry.category for entry, _ in pairs}),
        difficulties=sorted({entry.difficulty for entry, _ in pairs}),
        required_check_frequency=dict(sorted(required_checks.items())),
        evidence_pattern_variants=evidence_variants,
        evidence_pattern_coverage_percentage=round(
            (evidence_variants / len(variants)) * 100 if variants else 100.0,
            1,
        ),
    )


def _json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _write_reports(result: BenchmarkAuditResult) -> None:
    result.json_report_path.parent.mkdir(parents=True, exist_ok=True)
    with result.json_report_path.open("w", encoding="utf-8") as file:
        json.dump(
            asdict(result),
            file,
            default=_json_default,
            indent=2,
            sort_keys=True,
        )
        file.write("\n")

    lines = [
        "# AgentGuard Benchmark Audit",
        "",
        "## Audit Summary",
        "",
        f"- Mode: {result.mode}",
        f"- Benchmarks: {result.total_benchmarks}",
        f"- Variants: {result.total_variants}",
        f"- Trials: {result.total_trials}",
        f"- Contracts passed: {result.passed_contracts}",
        f"- Contracts failed: {result.failed_contracts}",
        f"- Unstable variants: {result.unstable_variants}",
        f"- Errors: {result.error_count}",
        f"- Warnings: {result.warning_count}",
        "",
        "## Static Validation",
        "",
    ]
    lines.extend(f"- {message}" for message in result.static_validation)
    lines.extend(
        [
            "",
            "## Contract Results",
            "",
            "| Benchmark | Variant | Status | Trials | Scores |",
            "|---|---|---|---:|---|",
        ]
    )
    for variant in result.variants:
        status = "PASS" if variant.passed else "FAIL"
        scores = ", ".join(str(score) for score in variant.observed_scores) or "-"
        lines.append(
            f"| {variant.benchmark_id} | {variant.variant} | {status} | "
            f"{len(variant.trials)} | {scores} |"
        )
    lines.extend(["", "## Unstable Variants", ""])
    unstable = [item for item in result.variants if item.unstable]
    lines.extend(
        [f"- {item.benchmark_id}/{item.variant}" for item in unstable]
        or ["- None"]
    )
    lines.extend(
        [
            "",
            "## Violations",
            "",
            "| Severity | Benchmark | Variant | Trial | Field | Message |",
            "|---|---|---|---:|---|---|",
        ]
    )
    for item in result.violations:
        lines.append(
            f"| {item.severity} | {item.benchmark_id} | {item.variant} | "
            f"{item.trial_index} | {item.field} | {item.message} |"
        )
    if not result.violations:
        lines.append("| - | - | - | - | - | None |")
    lines.extend(["", "## Individual Reports", ""])
    report_lines = [
        f"- {trial.benchmark_id}/{trial.variant} trial {trial.trial_index}: "
        f"{trial.report_path or '-'}; manifest {trial.manifest_path or '-'}"
        for variant in result.variants
        for trial in variant.trials
    ]
    lines.extend(report_lines or ["- Static audit; no benchmark runs executed."])
    result.markdown_report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _selected_pairs(
    pairs: list[tuple[BenchmarkRegistryEntry, BenchmarkContract]],
    benchmark_ids: list[str],
    category: Optional[str],
    difficulty: Optional[str],
    tags: list[str],
) -> list[tuple[BenchmarkRegistryEntry, BenchmarkContract]]:
    known = {entry.id for entry, _ in pairs}
    missing = [benchmark_id for benchmark_id in benchmark_ids if benchmark_id not in known]
    if missing:
        raise ValueError(f"Unknown benchmark ids: {', '.join(missing)}")
    selected = [
        pair
        for pair in pairs
        if (not benchmark_ids or pair[0].id in benchmark_ids)
        and (category is None or pair[0].category == category)
        and (difficulty is None or pair[0].difficulty == difficulty)
        and (not tags or set(tags).issubset(set(pair[0].tags)))
    ]
    if not selected:
        raise ValueError("Benchmark audit filters matched no contracts.")
    return selected


def run_benchmark_audit(
    registry_path: Path = DEFAULT_REGISTRY_PATH,
    *,
    benchmark_ids: Optional[list[str]] = None,
    static_only: bool = False,
    trials: int = 1,
    workers: int = 1,
    output_dir: Optional[Path] = None,
    strict_unexpected_checks: bool = False,
    category: Optional[str] = None,
    difficulty: Optional[str] = None,
    tags: Optional[list[str]] = None,
    benchmark_runner: Optional[Callable[[Path, str], BenchmarkResult]] = None,
) -> BenchmarkAuditResult:
    if isinstance(trials, bool) or not isinstance(trials, int) or trials <= 0:
        raise ValueError("Benchmark audit trials must be a positive integer.")
    if isinstance(workers, bool) or not isinstance(workers, int) or workers <= 0:
        raise ValueError("Benchmark audit workers must be a positive integer.")
    normalized_ids = normalize_registry_values(benchmark_ids)
    normalized_tags = normalize_registry_values(tags)
    registry = load_benchmark_registry(registry_path)
    all_pairs = load_registry_contracts(registry)
    pairs = _selected_pairs(
        all_pairs,
        normalized_ids,
        category,
        difficulty,
        normalized_tags,
    )
    started = time.monotonic()
    audit_id = _audit_id()
    audit_dir = (output_dir or Path(".agentguard/audits")) / audit_id
    variants: list[ContractVariantAudit] = []

    if static_only:
        for entry, contract in pairs:
            for variant in contract.variants:
                variants.append(
                    ContractVariantAudit(
                        benchmark_id=entry.id,
                        variant=variant.name,
                        config_path=variant.config,
                        passed=True,
                        unstable=False,
                        trials=[],
                        violations=[],
                        observed_results=[],
                        observed_functional_results=[],
                        observed_scores=[],
                        observed_failed_check_sets=[],
                        observed_modified_file_sets=[],
                    )
                )
    else:
        jobs = [
            (index, entry, variant, trial_index)
            for index, (entry, contract) in enumerate(pairs)
            for variant in contract.variants
            for trial_index in range(1, trials + 1)
        ]
        trial_results: dict[tuple[str, str], list[ContractTrialResult]] = {}

        def execute(
            entry: BenchmarkRegistryEntry,
            variant: ContractVariant,
            trial_index: int,
        ) -> ContractTrialResult:
            try:
                runner = benchmark_runner or (
                    lambda config_path, agent: run_benchmark(config_path, agent)
                )
                result = runner(variant.config, "custom-command")
                return evaluate_contract_result(
                    entry.id,
                    variant,
                    trial_index,
                    result,
                    strict_unexpected_checks=strict_unexpected_checks,
                )
            except Exception as error:
                return _runtime_failure(entry.id, variant, trial_index, error)

        ordered: dict[int, ContractTrialResult] = {}
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures: dict[Future[ContractTrialResult], int] = {
                executor.submit(execute, entry, variant, trial_index): job_index
                for job_index, (_, entry, variant, trial_index) in enumerate(jobs)
            }
            for future in as_completed(futures):
                ordered[futures[future]] = future.result()
        for job_index, (_, entry, variant, _) in enumerate(jobs):
            trial_results.setdefault((entry.id, variant.name), []).append(
                ordered[job_index]
            )
        for entry, contract in pairs:
            for variant in contract.variants:
                variants.append(
                    _variant_audit(
                        entry.id,
                        variant,
                        trial_results[(entry.id, variant.name)],
                    )
                )

    violations = [item for variant in variants for item in variant.violations]
    result = BenchmarkAuditResult(
        audit_id=audit_id,
        schema=AUDIT_SCHEMA,
        schema_version=AUDIT_SCHEMA_VERSION,
        mode="static" if static_only else "execution",
        selected_benchmarks=[entry.id for entry, _ in pairs],
        trials=trials,
        workers=workers,
        total_benchmarks=len(pairs),
        total_variants=len(variants),
        total_trials=0 if static_only else len(variants) * trials,
        passed_contracts=sum(variant.passed for variant in variants),
        failed_contracts=sum(not variant.passed for variant in variants),
        unstable_variants=sum(variant.unstable for variant in variants),
        warning_count=sum(item.severity == "warning" for item in violations),
        error_count=sum(item.severity == "error" for item in violations),
        variants=variants,
        violations=violations,
        corpus_metrics=_corpus_metrics(all_pairs, len(registry.benchmarks)),
        duration_seconds=round(time.monotonic() - started, 6),
        json_report_path=audit_dir / "audit.json",
        markdown_report_path=audit_dir / "audit.md",
        static_validation=[
            f"Validated {len(registry.benchmarks)} registry entries.",
            f"Validated {len(all_pairs)} benchmark contracts.",
            f"Validated {sum(len(contract.variants) for _, contract in all_pairs)} variants.",
        ],
    )
    _write_reports(result)
    return result
