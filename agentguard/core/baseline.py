from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from agentguard.io import atomic_write_json
from agentguard.core.baseline_validation import (
    load_baseline_json,
    require_fields,
    require_int,
    require_number,
    require_string,
)

BASELINE_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class BaselineRun:
    task_id: str
    agent: str
    config_path: str
    result: str
    score: int
    failed_checks: list[str]
    warning_checks: list[str]
    benchmark_id: Optional[str] = None
    benchmark_version: Optional[int] = None


@dataclass(frozen=True)
class SuiteBaseline:
    schema_version: int
    suite_id: str
    description: str
    created_at: str
    pass_rate: float
    average_score: int
    result_counts: dict[str, int]
    failed_check_counts: dict[str, int]
    runs: dict[str, BaselineRun]


@dataclass(frozen=True)
class BaselineComparison:
    baseline_path: str
    has_regressions: bool
    regressions: list[str]
    improvements: list[str]
    unchanged_count: int
    version_mismatches: list[str]


def _json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _portable_path(path: Path) -> str:
    resolved = path.expanduser().resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _run_id(task_id: str, agent: str, config_path: str) -> str:
    return f"{task_id}/{agent}/{config_path}"


def _display_run(run: BaselineRun) -> str:
    return f"{run.task_id}/{run.agent}"


def _version_mismatch_message(
    run_label: str,
    baseline_run: BaselineRun,
    current_run: BaselineRun,
) -> str:
    benchmark_label = (
        current_run.benchmark_id
        or baseline_run.benchmark_id
        or current_run.task_id
    )
    return (
        f"Benchmark version mismatch for {run_label} "
        f"({benchmark_label}): baseline {baseline_run.benchmark_version} "
        f"-> current {current_run.benchmark_version}"
    )


def baseline_from_suite_result(result: Any, created_at: Optional[str] = None) -> SuiteBaseline:
    timestamp = created_at or datetime.now(timezone.utc).isoformat()
    runs: dict[str, BaselineRun] = {}
    for run in result.runs:
        config_path = _portable_path(run.config_path)
        baseline_run = BaselineRun(
            task_id=run.task_id,
            agent=run.agent,
            config_path=config_path,
            result=run.result,
            score=run.score,
            failed_checks=sorted(run.failed_checks),
            warning_checks=sorted(run.warning_checks),
            benchmark_id=getattr(run, "benchmark_id", None),
            benchmark_version=getattr(run, "benchmark_version", None),
        )
        runs[_run_id(run.task_id, run.agent, config_path)] = baseline_run

    return SuiteBaseline(
        schema_version=BASELINE_SCHEMA_VERSION,
        suite_id=result.suite_id,
        description=result.description,
        created_at=timestamp,
        pass_rate=result.pass_rate,
        average_score=result.average_score,
        result_counts=dict(sorted(result.result_counts.items())),
        failed_check_counts=dict(sorted(result.failed_check_counts.items())),
        runs=dict(sorted(runs.items())),
    )


def write_suite_baseline(result: Any, path: Path) -> Path:
    baseline = baseline_from_suite_result(result)
    output_path = path.expanduser()
    atomic_write_json(output_path, asdict(baseline), default=_json_default)
    return output_path


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ValueError(f"{label} must be a list of non-empty strings.")
    if len(value) != len(set(value)):
        raise ValueError(f"{label} must not contain duplicates.")
    return list(value)


def _count_mapping(value: Any, label: str) -> dict[str, int]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object.")
    counts: dict[str, int] = {}
    for key, count in value.items():
        name = require_string(key, f"{label} key")
        counts[name] = require_int(count, f"{label} value", minimum=0)
    return counts


def _baseline_run_from_dict(data: dict[str, Any], run_id: str) -> BaselineRun:
    label = "Baseline run entry"
    require_fields(
        data,
        required={
            "task_id",
            "agent",
            "config_path",
            "result",
            "score",
            "failed_checks",
            "warning_checks",
        },
        optional={"benchmark_id", "benchmark_version"},
        label=label,
    )
    result = require_string(data["result"], f"{label} field 'result'")
    if result not in {"PASS", "FAIL"}:
        raise ValueError(f"{label} field 'result' must be PASS or FAIL.")
    benchmark_id = data.get("benchmark_id")
    if benchmark_id is not None:
        benchmark_id = require_string(benchmark_id, f"{label} field 'benchmark_id'")
    benchmark_version = data.get("benchmark_version")
    if benchmark_version is not None:
        benchmark_version = require_int(
            benchmark_version,
            f"{label} field 'benchmark_version'",
            minimum=1,
        )
    run = BaselineRun(
        task_id=require_string(data["task_id"], f"{label} field 'task_id'"),
        agent=require_string(data["agent"], f"{label} field 'agent'"),
        config_path=require_string(
            data["config_path"], f"{label} field 'config_path'"
        ),
        result=result,
        score=require_int(data["score"], f"{label} field 'score'", minimum=0, maximum=100),
        failed_checks=_string_list(data["failed_checks"], f"{label} field 'failed_checks'"),
        warning_checks=_string_list(
            data["warning_checks"], f"{label} field 'warning_checks'"
        ),
        benchmark_id=benchmark_id,
        benchmark_version=benchmark_version,
    )
    if run_id != _run_id(run.task_id, run.agent, run.config_path):
        raise ValueError(f"{label} identity does not match its object key.")
    return run


def load_suite_baseline(path: Path) -> SuiteBaseline:
    data = load_baseline_json(path, "baseline")
    if not isinstance(data, dict):
        raise ValueError("Baseline must be a JSON object.")
    require_fields(
        data,
        required={
            "schema_version",
            "suite_id",
            "description",
            "created_at",
            "pass_rate",
            "average_score",
            "result_counts",
            "failed_check_counts",
            "runs",
        },
        label="Baseline",
    )
    if data["schema_version"] != BASELINE_SCHEMA_VERSION or isinstance(
        data["schema_version"], bool
    ):
        raise ValueError("Baseline schema_version must be 1.")
    raw_runs = data["runs"]
    if not isinstance(raw_runs, dict):
        raise ValueError("Baseline field 'runs' must be an object.")
    if not raw_runs:
        raise ValueError("Baseline field 'runs' must not be empty.")
    runs: dict[str, BaselineRun] = {}
    identities: set[tuple[str, str, str]] = set()
    for run_id, raw_run in raw_runs.items():
        safe_run_id = require_string(run_id, "Baseline run key")
        if not isinstance(raw_run, dict):
            raise ValueError("Baseline run entry must be an object.")
        run = _baseline_run_from_dict(raw_run, safe_run_id)
        identity = (run.task_id, run.agent, run.config_path)
        if identity in identities:
            raise ValueError("Baseline contains duplicate run identities.")
        identities.add(identity)
        runs[safe_run_id] = run

    result_counts = _count_mapping(data["result_counts"], "Baseline result_counts")
    if set(result_counts) - {"PASS", "FAIL"}:
        raise ValueError("Baseline result_counts contains an unsupported result.")
    expected_result_counts = dict(Counter(run.result for run in runs.values()))
    if result_counts != expected_result_counts:
        raise ValueError("Baseline result_counts does not match its runs.")
    failed_check_counts = _count_mapping(
        data["failed_check_counts"], "Baseline failed_check_counts"
    )
    expected_failed_counts = dict(
        Counter(check for run in runs.values() for check in run.failed_checks)
    )
    if failed_check_counts != expected_failed_counts:
        raise ValueError("Baseline failed_check_counts does not match its runs.")
    pass_rate = require_number(
        data["pass_rate"], "Baseline field 'pass_rate'", minimum=0, maximum=100
    )
    expected_pass_rate = round(
        (expected_result_counts.get("PASS", 0) / len(runs)) * 100,
        1,
    )
    if pass_rate != expected_pass_rate:
        raise ValueError("Baseline pass_rate does not match its runs.")
    average_score = require_int(
        data["average_score"],
        "Baseline field 'average_score'",
        minimum=0,
        maximum=100,
    )
    if average_score != int(round(sum(run.score for run in runs.values()) / len(runs))):
        raise ValueError("Baseline average_score does not match its runs.")

    return SuiteBaseline(
        schema_version=BASELINE_SCHEMA_VERSION,
        suite_id=require_string(data["suite_id"], "Baseline field 'suite_id'"),
        description=require_string(
            data["description"], "Baseline field 'description'", allow_empty=True
        ),
        created_at=require_string(data["created_at"], "Baseline field 'created_at'"),
        pass_rate=pass_rate,
        average_score=average_score,
        result_counts=result_counts,
        failed_check_counts=failed_check_counts,
        runs=runs,
    )


def compare_suite_to_baseline(
    result: Any,
    baseline_path: Path,
    allow_version_mismatch: bool = False,
    only_compare_current_runs: bool = False,
) -> BaselineComparison:
    baseline = load_suite_baseline(baseline_path)
    current = baseline_from_suite_result(result, created_at=baseline.created_at)
    baseline_runs = baseline.runs
    if only_compare_current_runs:
        baseline_runs = {
            run_id: run
            for run_id, run in baseline.runs.items()
            if run_id in current.runs
        }
    regressions: list[str] = []
    improvements: list[str] = []
    version_mismatches: list[str] = []
    unchanged_count = 0

    baseline_pass_rate = baseline.pass_rate
    baseline_average_score = baseline.average_score
    if only_compare_current_runs and baseline_runs:
        baseline_passed = sum(1 for run in baseline_runs.values() if run.result == "PASS")
        baseline_pass_rate = round((baseline_passed / len(baseline_runs)) * 100, 1)
        baseline_average_score = int(
            round(sum(run.score for run in baseline_runs.values()) / len(baseline_runs))
        )

    if current.pass_rate < baseline_pass_rate:
        regressions.append(
            f"Pass rate decreased: {baseline_pass_rate} -> {current.pass_rate}"
        )
    elif current.pass_rate > baseline_pass_rate:
        improvements.append(
            f"Pass rate increased: {baseline_pass_rate} -> {current.pass_rate}"
        )

    if current.average_score < baseline_average_score:
        regressions.append(
            "Average score decreased: "
            f"{baseline_average_score} -> {current.average_score}"
        )
    elif current.average_score > baseline_average_score:
        improvements.append(
            "Average score increased: "
            f"{baseline_average_score} -> {current.average_score}"
        )

    for run_id, baseline_run in baseline_runs.items():
        current_run = current.runs.get(run_id)
        if current_run is None:
            regressions.append(f"Baseline run missing: {_display_run(baseline_run)}")
            continue

        changed = False
        run_label = _display_run(current_run)
        if (
            baseline_run.benchmark_version is not None
            and current_run.benchmark_version is not None
            and baseline_run.benchmark_version != current_run.benchmark_version
        ):
            version_mismatches.append(
                _version_mismatch_message(run_label, baseline_run, current_run)
            )
            changed = True

        if baseline_run.result == "PASS" and current_run.result == "FAIL":
            regressions.append(f"Run {run_label} changed PASS -> FAIL")
            changed = True
        elif baseline_run.result == "FAIL" and current_run.result == "PASS":
            improvements.append(f"Run {run_label} changed FAIL -> PASS")
            changed = True

        if current_run.score < baseline_run.score:
            regressions.append(
                f"Run {run_label} score decreased: "
                f"{baseline_run.score} -> {current_run.score}"
            )
            changed = True
        elif current_run.score > baseline_run.score:
            improvements.append(
                f"Run {run_label} score increased: "
                f"{baseline_run.score} -> {current_run.score}"
            )
            changed = True

        baseline_failed = set(baseline_run.failed_checks)
        current_failed = set(current_run.failed_checks)
        for check in sorted(current_failed - baseline_failed):
            regressions.append(f"New failed check for {run_label}: {check}")
            changed = True
        for check in sorted(baseline_failed - current_failed):
            improvements.append(f"Failed check disappeared for {run_label}: {check}")
            changed = True

        if not changed:
            unchanged_count += 1

    if version_mismatches and not allow_version_mismatch:
        details = "\n".join(f"- {message}" for message in version_mismatches)
        raise ValueError(
            "Benchmark version mismatch between suite and baseline:\n"
            f"{details}\n"
            "Use --allow-version-mismatch to compare anyway."
        )

    return BaselineComparison(
        baseline_path=baseline_path.expanduser().as_posix(),
        has_regressions=bool(regressions),
        regressions=regressions,
        improvements=improvements,
        unchanged_count=unchanged_count,
        version_mismatches=version_mismatches,
    )
