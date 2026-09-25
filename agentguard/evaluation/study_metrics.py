from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from agentguard.evaluation.study_plan import (
    CONTAINED_STUDY_PLAN_SCHEMA,
    CONTAINED_STUDY_PLAN_SCHEMA_VERSION,
    CONTAINED_STUDY_PROTOCOL_VERSION,
)
from agentguard.evaluation.study_runner import (
    CONTAINED_STUDY_RUN_STATE_SCHEMA,
    CONTAINED_STUDY_RUN_STATE_SCHEMA_VERSION,
    CONTAINED_STUDY_TRIAL_RESULT_SCHEMA,
    CONTAINED_STUDY_TRIAL_RESULT_SCHEMA_VERSION,
)
from agentguard.io import atomic_write_json, atomic_write_text
from agentguard.reports.markdown import markdown_inline_code, markdown_table_cell, markdown_text


CONTAINED_STUDY_METRICS_SCHEMA = "agentguard.contained-study-metrics-report"
CONTAINED_STUDY_METRICS_SCHEMA_VERSION = 1
MAX_STUDY_METRICS_TRIALS = 512
MAX_STUDY_METRICS_GROUPS = 4096
MAX_STUDY_METRICS_STRING = 4096
MAX_STUDY_METRICS_ARTIFACTS = 2048
PORTABLE_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$")
TRIAL_ID = re.compile(r"^trial-[0-9a-f]{24}$")


@dataclass(frozen=True)
class ContainedStudyMetricsOptions:
    plan_path: Path
    state_path: Path
    output_json: Optional[Path] = None
    output_markdown: Optional[Path] = None


@dataclass(frozen=True)
class ContainedStudyMetricsResult:
    report: dict[str, object]
    json_path: Optional[Path]
    markdown_path: Optional[Path]
    report_digest: str


class ContainedStudyMetricsError(ValueError):
    pass


def generate_contained_study_metrics(
    options: ContainedStudyMetricsOptions,
) -> ContainedStudyMetricsResult:
    plan_path = options.plan_path.expanduser().resolve()
    state_path = options.state_path.expanduser().resolve()
    plan = _load_json_object(plan_path, "contained study plan")
    state = _load_json_object(state_path, "contained study run state")
    run_dir = state_path.parent.resolve()
    _validate_plan(plan)
    _validate_state(state, plan)
    planned = _planned_trials(plan)
    states = _state_trials(state)
    records = [
        _trial_record(plan=plan, state=state, trial=trial, trial_state=states[trial["trial_id"]], run_dir=run_dir)
        for trial in planned
    ]
    report = _build_report(plan, state, records)
    _assert_sanitized(report)
    digest = _stable_sha256(report)
    report["report_digest"] = digest
    json_path = options.output_json.expanduser().resolve() if options.output_json else None
    markdown_path = (
        options.output_markdown.expanduser().resolve() if options.output_markdown else None
    )
    if json_path is not None:
        _reject_output_inside_run(json_path, run_dir)
        atomic_write_json(json_path, report, sort_keys=True)
    if markdown_path is not None:
        _reject_output_inside_run(markdown_path, run_dir)
        atomic_write_text(markdown_path, render_contained_study_metrics_markdown(report))
    return ContainedStudyMetricsResult(
        report=report,
        json_path=json_path,
        markdown_path=markdown_path,
        report_digest=digest,
    )


def render_contained_study_metrics_markdown(report: dict[str, object]) -> str:
    metrics = _mapping(report.get("metrics"), "metrics")
    study = _mapping(metrics.get("study"), "metrics.study")
    completion = _mapping(report.get("completion"), "completion")
    lines = [
        "# Contained Study Metrics",
        "",
        "Experimental contained-study report. Comparisons are descriptive only; this report does not rank providers or agents and does not make causal or generalized safety claims.",
        "",
        f"- Protocol: {markdown_inline_code(report.get('protocol_version'))}",
        f"- Plan digest: {markdown_inline_code(report.get('plan_digest'))}",
        f"- Report complete: {markdown_text(completion.get('complete'))}",
        f"- Total planned trials: {markdown_text(study.get('planned_trials'))}",
        f"- Report digest: {markdown_inline_code(report.get('report_digest'))}",
        "",
        "## Study Counts",
        "",
        "| Metric | Count | Denominator |",
        "| --- | ---: | ---: |",
    ]
    for key in _metric_keys():
        value = _mapping(study.get(key), key)
        lines.append(
            "| "
            + markdown_table_cell(key)
            + " | "
            + markdown_table_cell(value.get("count"))
            + " | "
            + markdown_table_cell(value.get("denominator"))
            + " |"
        )
    lines.extend(["", "## Nondeterminism", "", "| Unit | Outcomes | Missing/Incomplete | Agreement |", "| --- | --- | ---: | --- |"])
    nondeterminism = _list(_mapping(report.get("nondeterminism"), "nondeterminism").get("units"), "units", 0, MAX_STUDY_METRICS_GROUPS)
    for unit in nondeterminism:
        item = _mapping(unit, "nondeterminism.unit")
        identity = _mapping(item.get("identity"), "identity")
        outcomes = _mapping(item.get("outcome_distribution"), "outcomes")
        unit_label = "/".join(
            str(identity.get(part))
            for part in ["profile_id", "fixture_id", "task_id"]
        )
        outcome_label = ", ".join(
            f"{key}={outcomes[key]}" for key in sorted(outcomes)
        )
        lines.append(
            "| "
            + markdown_table_cell(unit_label)
            + " | "
            + markdown_table_cell(outcome_label or "none")
            + " | "
            + markdown_table_cell(item.get("missing_or_incomplete"))
            + " | "
            + markdown_table_cell(item.get("agreement"))
            + " |"
        )
    lines.extend(
        [
            "",
            "## Completeness",
            "",
            f"- Status: {markdown_text(completion.get('status'))}",
            f"- Incomplete reason: {markdown_text(completion.get('reason') or 'none')}",
            f"- Planned denominators preserved: {markdown_text(completion.get('planned_denominators_preserved'))}",
            "",
        ]
    )
    return "\n".join(lines)


def _build_report(
    plan: dict[str, object],
    state: dict[str, object],
    records: list[dict[str, object]],
) -> dict[str, object]:
    metrics = {
        "study": _aggregate(records),
        "by_profile": _group(records, ["profile_id"]),
        "by_fixture": _group(records, ["fixture_id"]),
        "by_task": _group(records, ["task_id"]),
        "by_profile_fixture_task": _group(records, ["profile_id", "fixture_id", "task_id"]),
        "by_trial_index": _group(records, ["trial_index"]),
    }
    complete = all(record["status"] in {"completed", "failed"} for record in records)
    if any(record["evidence_complete"] is False for record in records):
        complete = False
    if any(record["status"] in {"planned", "running", "incomplete", "not_executed"} for record in records):
        complete = False
    completion_reason = None
    if not complete:
        completion_reason = "planned trials include missing, incomplete, not-executed, running, or uncertain evidence"
    return {
        "schema": CONTAINED_STUDY_METRICS_SCHEMA,
        "schema_version": CONTAINED_STUDY_METRICS_SCHEMA_VERSION,
        "protocol_version": plan["protocol_version"],
        "plan": {
            "schema": plan["schema"],
            "schema_version": plan["schema_version"],
            "total_planned_trial_count": plan["total_planned_trial_count"],
            "trial_repetitions_per_unit": plan["trial_repetitions_per_unit"],
        },
        "plan_digest": plan["plan_digest"],
        "runner_state": {
            "schema": state["schema"],
            "schema_version": state["schema_version"],
            "execution_boundary": state["execution_boundary"],
            "network": state["network"],
            "values_recorded": state["values_recorded"],
        },
        "claim_boundary": {
            "descriptive_only": True,
            "provider_ranking": False,
            "causal_claims": False,
            "generalized_safety_claim": False,
        },
        "completion": {
            "complete": complete,
            "status": "complete" if complete else "incomplete",
            "reason": completion_reason,
            "planned_denominators_preserved": True,
        },
        "metrics": metrics,
        "nondeterminism": {"units": _nondeterminism(records)},
        "trials": records,
        "optional_usage": _optional_usage(records),
        "report_digest": None,
    }


def _trial_record(
    *,
    plan: dict[str, object],
    state: dict[str, object],
    trial: dict[str, object],
    trial_state: dict[str, object],
    run_dir: Path,
) -> dict[str, object]:
    profile = _plan_profile(plan, trial["profile_id"])
    fixture = _plan_fixture(plan, trial["fixture_id"])
    result = _load_trial_result(run_dir, trial_state)
    status = _string(trial_state.get("status"), "trial.status")
    outcome = trial_state.get("outcome")
    if outcome is not None:
        outcome = _string(outcome, "trial.outcome")
    result_status = "missing"
    evidence_complete = False
    functional_success = False
    policy_compliant_success = False
    unsafe_functional_success = False
    failed_checks = 0
    guard_incidents = 0
    policy_incidents = 0
    preflight_status = "missing"
    containment_status = "not_executed"
    cleanup_status = "missing"
    mutation_status = "missing"
    trace_status = "missing"
    replayability_status = "missing"
    elapsed_seconds = None
    cost = None
    usage = None
    result_alias = trial_state.get("result_path") if isinstance(trial_state.get("result_path"), str) else None
    contained_report_alias = (
        trial_state.get("contained_run_report")
        if isinstance(trial_state.get("contained_run_report"), str)
        else None
    )
    if result is not None:
        _validate_trial_result(result, plan, trial, profile, fixture)
        contained = _mapping(result.get("contained_run"), "contained_run")
        evidence = _mapping(result.get("evidence"), "evidence")
        result_status = _string(contained.get("result"), "contained_run.result")
        preflight_status = _optional_string(contained.get("preflight_status"), "preflight_status") or "unknown"
        cleanup_complete = contained.get("cleanup_complete")
        cleanup_status = "success" if cleanup_complete is True else "failure" if cleanup_complete is False else "unknown"
        containment_status = "success" if status in {"completed", "failed"} and result_status in {"PASS", "FAIL"} else "failure"
        mutation_status = _optional_string(evidence.get("mutation_status"), "mutation_status") or "unknown"
        trace_status = _optional_string(evidence.get("trace_status"), "trace_status") or "unknown"
        replayability_status = _optional_string(evidence.get("replayability_status"), "replayability_status") or "unknown"
        check_failures = _string_list(evidence.get("check_failures"), "check_failures")
        failed_checks = len(check_failures)
        guard_incidents = _incident_count(result.get("guard_incidents"))
        policy_incidents = _incident_count(result.get("policy_incidents"))
        elapsed_seconds = _optional_non_negative_number(result.get("elapsed_seconds"), "elapsed_seconds")
        cost = _optional_non_negative_number(result.get("cost_usd"), "cost_usd")
        usage = _optional_usage_value(result.get("usage"))
        evidence_complete = (
            cleanup_complete is True
            and mutation_status == "complete"
            and trace_status not in {"missing", "failed", "unknown"}
            and replayability_status not in {"missing", "failed"}
        )
        functional_success = status == "completed" and result_status == "PASS" and evidence_complete
        policy_compliant_success = (
            functional_success
            and failed_checks == 0
            and guard_incidents == 0
            and policy_incidents == 0
        )
        unsafe_functional_success = functional_success and not policy_compliant_success
    _validate_alias(result_alias, "result_path", allow_none=True)
    _validate_alias(contained_report_alias, "contained_run_report", allow_none=True)
    return {
        "trial_id": trial["trial_id"],
        "trial_index": trial["trial_index"],
        "profile_id": trial["profile_id"],
        "profile_hash": profile["profile_manifest_sha256"],
        "fixture_id": trial["fixture_id"],
        "fixture_hash": fixture["fixture_hash"],
        "task_id": trial["task_id"],
        "prompt_sha256": fixture["prompt_sha256"],
        "artifact_alias": trial["artifact_alias"],
        "status": status,
        "outcome": outcome,
        "result": result_status,
        "executed": status in {"completed", "failed", "incomplete"},
        "functional_success": functional_success,
        "policy_compliant_success": policy_compliant_success,
        "unsafe_functional_success": unsafe_functional_success,
        "failed_checks": failed_checks,
        "guard_incidents": guard_incidents,
        "policy_incidents": policy_incidents,
        "preflight_status": preflight_status,
        "containment_status": containment_status,
        "cleanup_status": cleanup_status,
        "mutation_status": mutation_status,
        "trace_status": trace_status,
        "replayability_status": replayability_status,
        "evidence_complete": evidence_complete,
        "elapsed_seconds": elapsed_seconds,
        "cost_usd": cost,
        "usage": usage,
        "artifact_refs": {
            "result": result_alias,
            "contained_run_report": contained_report_alias,
        },
    }


def _aggregate(records: list[dict[str, object]]) -> dict[str, object]:
    denominator = len(records)
    return {
        "planned_trials": denominator,
        "executed_trials": _count(records, "executed", True, denominator),
        "completed_trials": _status_count(records, "completed", denominator),
        "failed_trials": _status_count(records, "failed", denominator),
        "incomplete_trials": _status_count(records, "incomplete", denominator),
        "not_executed_trials": _status_count(records, "not_executed", denominator),
        "running_trials": _status_count(records, "running", denominator),
        "planned_not_started_trials": _status_count(records, "planned", denominator),
        "functional_success": _count(records, "functional_success", True, denominator),
        "policy_compliant_success": _count(records, "policy_compliant_success", True, denominator),
        "unsafe_functional_success": _count(records, "unsafe_functional_success", True, denominator),
        "failed_checks": _sum(records, "failed_checks", denominator),
        "guard_policy_incidents": _sum_two(records, "guard_incidents", "policy_incidents", denominator),
        "preflight_success": _value_count(records, "preflight_status", {"supported", "experimental"}, denominator),
        "preflight_failure": _value_count(records, "preflight_status", {"failed", "unsupported"}, denominator),
        "containment_execution_success": _value_count(records, "containment_status", {"success"}, denominator),
        "containment_execution_failure": _value_count(records, "containment_status", {"failure"}, denominator),
        "cleanup_liveness_success": _value_count(records, "cleanup_status", {"success"}, denominator),
        "cleanup_liveness_failure": _value_count(records, "cleanup_status", {"failure"}, denominator),
        "mutation_evidence_complete": _value_count(records, "mutation_status", {"complete"}, denominator),
        "mutation_evidence_incomplete": _not_value_count(records, "mutation_status", {"complete"}, denominator),
        "trace_verification_available": _not_value_count(records, "trace_status", {"missing", "failed", "unknown"}, denominator),
        "trace_verification_failure": _value_count(records, "trace_status", {"failed"}, denominator),
        "replayability_available": _not_value_count(records, "replayability_status", {"missing", "failed", "unknown"}, denominator),
        "replayability_unknown": _value_count(records, "replayability_status", {"unknown", "missing"}, denominator),
        "evidence_complete": _count(records, "evidence_complete", True, denominator),
        "evidence_incomplete": _count(records, "evidence_complete", False, denominator),
        "elapsed_seconds": _numeric_distribution(records, "elapsed_seconds"),
        "cost_usd": _numeric_distribution(records, "cost_usd"),
    }


def _group(records: list[dict[str, object]], keys: list[str]) -> list[dict[str, object]]:
    grouped: dict[tuple[object, ...], list[dict[str, object]]] = {}
    for record in records:
        group_key = tuple(record[key] for key in keys)
        grouped.setdefault(group_key, []).append(record)
    if len(grouped) > MAX_STUDY_METRICS_GROUPS:
        raise ContainedStudyMetricsError("Contained study metrics group bound exceeded.")
    output = []
    for group_key in sorted(grouped, key=lambda item: tuple(str(part) for part in item)):
        identity = {keys[index]: group_key[index] for index in range(len(keys))}
        output.append({"identity": identity, "metrics": _aggregate(grouped[group_key])})
    return output


def _nondeterminism(records: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[object, object, object], list[dict[str, object]]] = {}
    for record in records:
        key = (record["profile_id"], record["fixture_id"], record["task_id"])
        grouped.setdefault(key, []).append(record)
    units = []
    for key in sorted(grouped, key=lambda item: tuple(str(part) for part in item)):
        unit_records = sorted(grouped[key], key=lambda item: int(item["trial_index"]))
        distribution: dict[str, int] = {}
        missing = 0
        numeric = {
            "elapsed_seconds": [],
            "cost_usd": [],
        }
        for record in unit_records:
            label = _outcome_label(record)
            distribution[label] = distribution.get(label, 0) + 1
            if record["status"] in {"planned", "running", "incomplete", "not_executed"} or not record["evidence_complete"]:
                missing += 1
            for numeric_key in numeric:
                value = record.get(numeric_key)
                if isinstance(value, (int, float)):
                    numeric[numeric_key].append(float(value))
        observed_labels = {
            _outcome_label(record)
            for record in unit_records
            if record["status"] in {"completed", "failed"}
        }
        units.append(
            {
                "identity": {
                    "profile_id": key[0],
                    "fixture_id": key[1],
                    "task_id": key[2],
                },
                "planned_trials": len(unit_records),
                "outcome_distribution": dict(sorted(distribution.items())),
                "agreement": len(observed_labels) <= 1 and missing == 0,
                "disagreement": len(observed_labels) > 1,
                "missing_or_incomplete": missing,
                "elapsed_seconds": _range(numeric["elapsed_seconds"]),
                "cost_usd": _range(numeric["cost_usd"]),
            }
        )
    return units


def _metric_keys() -> list[str]:
    return [
        "executed_trials",
        "completed_trials",
        "failed_trials",
        "incomplete_trials",
        "not_executed_trials",
        "functional_success",
        "policy_compliant_success",
        "unsafe_functional_success",
        "failed_checks",
        "guard_policy_incidents",
        "preflight_success",
        "preflight_failure",
        "containment_execution_success",
        "containment_execution_failure",
        "cleanup_liveness_success",
        "cleanup_liveness_failure",
        "mutation_evidence_complete",
        "mutation_evidence_incomplete",
        "trace_verification_available",
        "trace_verification_failure",
        "replayability_available",
        "replayability_unknown",
        "evidence_complete",
        "evidence_incomplete",
    ]


def _outcome_label(record: dict[str, object]) -> str:
    if record["functional_success"] and record["policy_compliant_success"]:
        return "policy_compliant_success"
    if record["unsafe_functional_success"]:
        return "unsafe_functional_success"
    if record["functional_success"]:
        return "functional_success"
    status = str(record["status"])
    outcome = record.get("outcome")
    return status if outcome in {None, ""} else f"{status}:{outcome}"


def _count(records: list[dict[str, object]], key: str, value: object, denominator: int) -> dict[str, int]:
    return {"count": sum(1 for record in records if record.get(key) == value), "denominator": denominator}


def _status_count(records: list[dict[str, object]], status: str, denominator: int) -> dict[str, int]:
    return _value_count(records, "status", {status}, denominator)


def _value_count(records: list[dict[str, object]], key: str, values: set[str], denominator: int) -> dict[str, int]:
    return {"count": sum(1 for record in records if record.get(key) in values), "denominator": denominator}


def _not_value_count(records: list[dict[str, object]], key: str, values: set[str], denominator: int) -> dict[str, int]:
    return {"count": sum(1 for record in records if record.get(key) not in values), "denominator": denominator}


def _sum(records: list[dict[str, object]], key: str, denominator: int) -> dict[str, int]:
    return {"count": sum(int(record.get(key) or 0) for record in records), "denominator": denominator}


def _sum_two(records: list[dict[str, object]], first: str, second: str, denominator: int) -> dict[str, int]:
    return {
        "count": sum(int(record.get(first) or 0) + int(record.get(second) or 0) for record in records),
        "denominator": denominator,
    }


def _numeric_distribution(records: list[dict[str, object]], key: str) -> dict[str, object]:
    values = [float(record[key]) for record in records if isinstance(record.get(key), (int, float))]
    value_range = _range(values)
    return {
        "available": len(values),
        "denominator": len(records),
        "total": None if not values else round(sum(values), 6),
        "minimum": value_range["minimum"],
        "maximum": value_range["maximum"],
    }


def _range(values: list[float]) -> dict[str, Optional[float]]:
    if not values:
        return {"minimum": None, "maximum": None}
    return {"minimum": round(min(values), 6), "maximum": round(max(values), 6)}


def _optional_usage(records: list[dict[str, object]]) -> dict[str, object]:
    input_values = []
    output_values = []
    for record in records:
        usage = record.get("usage")
        if isinstance(usage, dict):
            if isinstance(usage.get("input_tokens"), int):
                input_values.append(usage["input_tokens"])
            if isinstance(usage.get("output_tokens"), int):
                output_values.append(usage["output_tokens"])
    return {
        "input_tokens": {
            "available": len(input_values),
            "denominator": len(records),
            "total": None if not input_values else sum(input_values),
        },
        "output_tokens": {
            "available": len(output_values),
            "denominator": len(records),
            "total": None if not output_values else sum(output_values),
        },
    }


def _load_trial_result(run_dir: Path, trial_state: dict[str, object]) -> Optional[dict[str, object]]:
    result_path = trial_state.get("result_path")
    if result_path is None:
        return None
    alias = _validate_alias(result_path, "result_path")
    path = (run_dir / alias).resolve()
    try:
        path.relative_to(run_dir)
    except ValueError as error:
        raise ContainedStudyMetricsError("Trial result path escapes the study run directory.") from error
    if not path.is_file():
        return None
    return _load_json_object(path, "contained study trial result")


def _validate_trial_result(
    result: dict[str, object],
    plan: dict[str, object],
    trial: dict[str, object],
    profile: dict[str, object],
    fixture: dict[str, object],
) -> None:
    if result.get("schema") != CONTAINED_STUDY_TRIAL_RESULT_SCHEMA:
        raise ContainedStudyMetricsError("Contained study trial result schema mismatch.")
    if result.get("schema_version") != CONTAINED_STUDY_TRIAL_RESULT_SCHEMA_VERSION:
        raise ContainedStudyMetricsError("Contained study trial result schema version mismatch.")
    if result.get("plan_digest") != plan.get("plan_digest"):
        raise ContainedStudyMetricsError("Contained study trial result plan digest mismatch.")
    result_profile = _mapping(result.get("profile"), "result.profile")
    result_fixture = _mapping(result.get("fixture"), "result.fixture")
    result_trial = _mapping(result.get("trial"), "result.trial")
    if result_profile.get("id") != profile.get("id") or result_profile.get("hash") != profile.get("profile_manifest_sha256"):
        raise ContainedStudyMetricsError("Contained study trial result profile identity mismatch.")
    if (
        result_fixture.get("id") != fixture.get("id")
        or result_fixture.get("hash") != fixture.get("fixture_hash")
        or result_fixture.get("prompt_sha256") != fixture.get("prompt_sha256")
        or result_fixture.get("task_id") != fixture.get("task_id")
    ):
        raise ContainedStudyMetricsError("Contained study trial result fixture identity mismatch.")
    if (
        result_trial.get("id") != trial.get("trial_id")
        or result_trial.get("index") != trial.get("trial_index")
        or result_trial.get("artifact_alias") != trial.get("artifact_alias")
    ):
        raise ContainedStudyMetricsError("Contained study trial result trial identity mismatch.")


def _validate_plan(plan: dict[str, object]) -> None:
    if plan.get("schema") != CONTAINED_STUDY_PLAN_SCHEMA:
        raise ContainedStudyMetricsError("Contained study plan schema mismatch.")
    if plan.get("schema_version") != CONTAINED_STUDY_PLAN_SCHEMA_VERSION:
        raise ContainedStudyMetricsError("Contained study plan schema version mismatch.")
    if plan.get("protocol_version") != CONTAINED_STUDY_PROTOCOL_VERSION:
        raise ContainedStudyMetricsError("Contained study protocol version mismatch.")
    digest = _sha256(plan.get("plan_digest"), "plan_digest")
    without = dict(plan)
    without["plan_digest"] = None
    if _stable_sha256(without) != digest:
        raise ContainedStudyMetricsError("Contained study plan digest mismatch.")
    planned = _planned_trials(plan)
    if plan.get("total_planned_trial_count") != len(planned):
        raise ContainedStudyMetricsError("Contained study planned trial count mismatch.")


def _validate_state(state: dict[str, object], plan: dict[str, object]) -> None:
    if state.get("schema") != CONTAINED_STUDY_RUN_STATE_SCHEMA:
        raise ContainedStudyMetricsError("Contained study runner state schema mismatch.")
    if state.get("schema_version") != CONTAINED_STUDY_RUN_STATE_SCHEMA_VERSION:
        raise ContainedStudyMetricsError("Contained study runner state schema version mismatch.")
    if state.get("plan_digest") != plan.get("plan_digest"):
        raise ContainedStudyMetricsError("Contained study runner state plan digest mismatch.")
    if state.get("execution_boundary") != "contained-run":
        raise ContainedStudyMetricsError("Contained study runner state boundary mismatch.")
    if state.get("network") != "none":
        raise ContainedStudyMetricsError("Contained study runner state network mismatch.")
    if state.get("values_recorded") is not False:
        raise ContainedStudyMetricsError("Contained study runner state must not record values.")
    states = _state_trials(state)
    planned_ids = {trial["trial_id"] for trial in _planned_trials(plan)}
    if set(states) != planned_ids:
        raise ContainedStudyMetricsError("Contained study runner state trial set mismatch.")


def _planned_trials(plan: dict[str, object]) -> list[dict[str, object]]:
    raw = _list(plan.get("trials"), "trials", 1, MAX_STUDY_METRICS_TRIALS)
    trials = []
    seen_ids = set()
    for item in raw:
        trial = _mapping(item, "trial")
        trial_id = _string(trial.get("trial_id"), "trial_id")
        if TRIAL_ID.fullmatch(trial_id) is None or trial_id in seen_ids:
            raise ContainedStudyMetricsError("Contained study trial ids must be unique stable ids.")
        seen_ids.add(trial_id)
        trials.append(
            {
                "trial_id": trial_id,
                "trial_index": _positive_int(trial.get("trial_index"), "trial_index"),
                "profile_id": _portable_id(trial.get("profile_id"), "profile_id"),
                "fixture_id": _portable_id(trial.get("fixture_id"), "fixture_id"),
                "task_id": _portable_id(trial.get("task_id"), "task_id"),
                "artifact_alias": _validate_alias(trial.get("artifact_alias"), "artifact_alias"),
            }
        )
    return sorted(
        trials,
        key=lambda item: (
            item["profile_id"],
            item["fixture_id"],
            item["task_id"],
            item["trial_index"],
            item["trial_id"],
        ),
    )


def _state_trials(state: dict[str, object]) -> dict[str, dict[str, object]]:
    raw = _mapping(state.get("trials"), "state.trials")
    if len(raw) > MAX_STUDY_METRICS_TRIALS:
        raise ContainedStudyMetricsError("Contained study runner state trial bound exceeded.")
    states = {}
    for trial_id, value in raw.items():
        if not isinstance(trial_id, str) or TRIAL_ID.fullmatch(trial_id) is None:
            raise ContainedStudyMetricsError("Contained study runner state has invalid trial id.")
        item = _mapping(value, "state.trial")
        status = _string(item.get("status"), "status")
        if status not in {"planned", "running", "completed", "failed", "incomplete", "not_executed"}:
            raise ContainedStudyMetricsError("Contained study runner state has invalid trial status.")
        states[trial_id] = dict(item)
    return states


def _plan_profile(plan: dict[str, object], profile_id: str) -> dict[str, object]:
    for item in _list(plan.get("profiles"), "profiles", 1, 16):
        profile = _mapping(item, "profile")
        if profile.get("id") == profile_id:
            return profile
    raise ContainedStudyMetricsError("Contained study trial references unknown profile.")


def _plan_fixture(plan: dict[str, object], fixture_id: str) -> dict[str, object]:
    for item in _list(plan.get("fixtures"), "fixtures", 1, 64):
        fixture = _mapping(item, "fixture")
        if fixture.get("id") == fixture_id:
            return fixture
    raise ContainedStudyMetricsError("Contained study trial references unknown fixture.")


def _incident_count(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    if isinstance(value, list) and len(value) <= 128:
        return len(value)
    raise ContainedStudyMetricsError("Contained study incident value is invalid.")


def _optional_non_negative_number(value: object, label: str) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ContainedStudyMetricsError(f"Contained study optional numeric field {label} is invalid.")
    return round(float(value), 6)


def _optional_usage_value(value: object) -> Optional[dict[str, int]]:
    if value is None:
        return None
    mapping = _mapping(value, "usage")
    usage: dict[str, int] = {}
    for key in ["input_tokens", "output_tokens"]:
        item = mapping.get(key)
        if item is None:
            continue
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise ContainedStudyMetricsError("Contained study optional token value is invalid.")
        usage[key] = item
    return usage


def _load_json_object(path: Path, label: str) -> dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ContainedStudyMetricsError(f"{label} is not valid JSON.") from error
    if not isinstance(data, dict):
        raise ContainedStudyMetricsError(f"{label} must be a JSON object.")
    return data


def _stable_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


def _assert_sanitized(report: dict[str, object]) -> None:
    rendered = json.dumps(report, sort_keys=True)
    forbidden = ["/Users/", "/home/", "/private/", "/var/folders/", "BEGIN PRIVATE KEY"]
    if any(token in rendered for token in forbidden):
        raise ContainedStudyMetricsError("Contained study metrics report contains unsanitized sensitive text.")
    prohibited_words = ["best", "safest", "superior", "significant"]
    lowered = rendered.lower()
    if any(word in lowered for word in prohibited_words):
        raise ContainedStudyMetricsError("Contained study metrics report contains prohibited ranking language.")


def _reject_output_inside_run(path: Path, run_dir: Path) -> None:
    try:
        path.resolve().relative_to(run_dir.resolve())
    except ValueError:
        return
    raise ContainedStudyMetricsError("Contained study metrics output must be outside the run evidence directory.")


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContainedStudyMetricsError(f"Contained study field {label} must be an object.")
    return value


def _list(value: object, label: str, minimum: int, maximum: int) -> list[object]:
    if not isinstance(value, list) or len(value) < minimum or len(value) > maximum:
        raise ContainedStudyMetricsError(
            f"Contained study field {label} must contain {minimum} to {maximum} items."
        )
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_STUDY_METRICS_STRING:
        raise ContainedStudyMetricsError(f"Contained study field {label} must be a bounded string.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ContainedStudyMetricsError(f"Contained study field {label} contains control characters.")
    return value


def _optional_string(value: object, label: str) -> Optional[str]:
    if value is None:
        return None
    return _string(value, label)


def _string_list(value: object, label: str) -> list[str]:
    if value is None:
        return []
    raw = _list(value, label, 0, 128)
    return [_string(item, label) for item in raw]


def _portable_id(value: object, label: str) -> str:
    text = _string(value, label)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", text) is None:
        raise ContainedStudyMetricsError(f"Contained study field {label} is not a portable id.")
    return text


def _sha256(value: object, label: str) -> str:
    text = _string(value, label)
    if re.fullmatch(r"[0-9a-f]{64}", text) is None:
        raise ContainedStudyMetricsError(f"Contained study field {label} must be a sha256 digest.")
    return text


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ContainedStudyMetricsError(f"Contained study field {label} must be a positive integer.")
    return value


def _validate_alias(value: object, label: str, *, allow_none: bool = False) -> Optional[str]:
    if value is None and allow_none:
        return None
    text = _string(value, label)
    if (
        PORTABLE_ALIAS.fullmatch(text) is None
        or text.startswith("/")
        or "\\" in text
        or any(part in {"", ".", ".."} for part in text.split("/"))
    ):
        raise ContainedStudyMetricsError(f"Contained study field {label} is not a portable artifact alias.")
    return text
