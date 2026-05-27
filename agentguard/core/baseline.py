import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


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
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(asdict(baseline), file, default=_json_default, indent=2)
        file.write("\n")
    return output_path


def _baseline_run_from_dict(data: dict[str, Any], run_id: str) -> BaselineRun:
    try:
        return BaselineRun(
            task_id=str(data["task_id"]),
            agent=str(data["agent"]),
            config_path=str(data["config_path"]),
            result=str(data["result"]),
            score=int(data["score"]),
            failed_checks=list(data.get("failed_checks", [])),
            warning_checks=list(data.get("warning_checks", [])),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"Invalid baseline run '{run_id}'.") from error


def load_suite_baseline(path: Path) -> SuiteBaseline:
    baseline_path = path.expanduser()
    try:
        with baseline_path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except OSError as error:
        raise ValueError(f"Could not read baseline: {baseline_path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"Baseline is not valid JSON: {baseline_path}") from error

    if not isinstance(data, dict):
        raise ValueError("Baseline must be a JSON object.")
    if data.get("schema_version") != BASELINE_SCHEMA_VERSION:
        raise ValueError("Baseline schema_version must be 1.")
    raw_runs = data.get("runs")
    if not isinstance(raw_runs, dict):
        raise ValueError("Baseline field 'runs' must be an object.")

    return SuiteBaseline(
        schema_version=BASELINE_SCHEMA_VERSION,
        suite_id=str(data.get("suite_id", "")),
        description=str(data.get("description", "")),
        created_at=str(data.get("created_at", "")),
        pass_rate=float(data.get("pass_rate", 0.0)),
        average_score=int(data.get("average_score", 0)),
        result_counts={
            str(key): int(value)
            for key, value in dict(data.get("result_counts", {})).items()
        },
        failed_check_counts={
            str(key): int(value)
            for key, value in dict(data.get("failed_check_counts", {})).items()
        },
        runs={
            str(run_id): _baseline_run_from_dict(run, str(run_id))
            for run_id, run in raw_runs.items()
            if isinstance(run, dict)
        },
    )


def compare_suite_to_baseline(result: Any, baseline_path: Path) -> BaselineComparison:
    baseline = load_suite_baseline(baseline_path)
    current = baseline_from_suite_result(result, created_at=baseline.created_at)
    regressions: list[str] = []
    improvements: list[str] = []
    unchanged_count = 0

    if current.pass_rate < baseline.pass_rate:
        regressions.append(
            f"Pass rate decreased: {baseline.pass_rate} -> {current.pass_rate}"
        )
    elif current.pass_rate > baseline.pass_rate:
        improvements.append(
            f"Pass rate increased: {baseline.pass_rate} -> {current.pass_rate}"
        )

    if current.average_score < baseline.average_score:
        regressions.append(
            "Average score decreased: "
            f"{baseline.average_score} -> {current.average_score}"
        )
    elif current.average_score > baseline.average_score:
        improvements.append(
            "Average score increased: "
            f"{baseline.average_score} -> {current.average_score}"
        )

    for run_id, baseline_run in baseline.runs.items():
        current_run = current.runs.get(run_id)
        if current_run is None:
            regressions.append(f"Baseline run missing: {_display_run(baseline_run)}")
            continue

        changed = False
        run_label = _display_run(current_run)
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

    return BaselineComparison(
        baseline_path=baseline_path.expanduser().as_posix(),
        has_regressions=bool(regressions),
        regressions=regressions,
        improvements=improvements,
        unchanged_count=unchanged_count,
    )
