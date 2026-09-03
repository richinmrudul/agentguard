"""Optional deterministic projection of execution traces for external verification.

This module only converts AgentGuard evidence.  It does not invoke a verifier,
perform network access, or alter AgentGuard scoring.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from agentguard.io import atomic_write_text
from agentguard.traces.execution import (
    EVENT_TYPES,
    ExecutionTrace,
    TraceEvent,
    canonical_json,
    load_execution_trace,
    verify_execution_trace,
)


POLICY_SCHEMA = "agentguard.verifier-projection-policy"
POLICY_SCHEMA_VERSION = 1
REPORT_SCHEMA = "agentguard.verifier-projection-report"
REPORT_SCHEMA_VERSION = 1
PROJECTION_CONTRACT = "bonfyre.agent_trace.v1"
VALID_STATUSES = {"succeeded", "failed", "cancelled"}
MAX_POLICY_BYTES = 256 * 1024
MAX_POLICY_ITEMS = 4096


@dataclass(frozen=True)
class VerifierProjectionArtifacts:
    """Canonical projected input and conversion report."""

    projection: dict[str, object]
    report: dict[str, object]
    projection_text: str
    report_text: str


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_text(value: object) -> str:
    return canonical_json(value) + "\n"


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Non-finite JSON number: {value}")


def _require_object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object.")
    return value


def _require_exact_fields(
    value: dict[str, Any], expected: set[str], label: str
) -> None:
    actual = set(value)
    if actual == expected:
        return
    details = []
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing:
        details.append(f"missing {', '.join(missing)}")
    if unknown:
        details.append(f"unknown {', '.join(unknown)}")
    raise ValueError(f"Invalid {label} fields: {'; '.join(details)}.")


def _require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError(f"{label} must be a nonempty string of at most 256 chars.")
    return value


def _require_string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_POLICY_ITEMS:
        raise ValueError(f"{label} must be a bounded array.")
    result = []
    for index, item in enumerate(value):
        result.append(_require_string(item, f"{label}[{index}]"))
    if len(result) != len(set(result)):
        raise ValueError(f"{label} must not contain duplicates.")
    return result


def _require_nonnegative_number(value: object, label: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError(f"{label} must be a nonnegative number.")
    return float(value)


def _validate_resource(value: object, label: str) -> None:
    resource = _require_object(value, label)
    kind = resource.get("kind")
    if kind == "constant":
        _require_exact_fields(resource, {"kind", "value"}, label)
        _require_string(resource["value"], f"{label}.value")
        return
    if kind == "repository_path":
        _require_exact_fields(resource, {"kind", "field", "prefix"}, label)
        _require_string(resource["field"], f"{label}.field")
        _require_string(resource["prefix"], f"{label}.prefix")
        return
    raise ValueError(f"{label}.kind is unsupported.")


def _validate_review(value: object, label: str) -> None:
    if value is None:
        return
    review = _require_object(value, label)
    _require_exact_fields(review, {"status", "reviewer"}, label)
    if review["status"] != "approved":
        raise ValueError(f"{label}.status must be approved.")
    _require_string(review["reviewer"], f"{label}.reviewer")


def validate_projection_policy(policy: object) -> dict[str, Any]:
    """Strictly validate and return an adapter policy object."""

    value = _require_object(policy, "adapter policy")
    _require_exact_fields(
        value,
        {
            "schema",
            "schema_version",
            "actor",
            "task",
            "verifier_policy",
            "event_rules",
            "outcome_rules",
        },
        "adapter policy",
    )
    if value["schema"] != POLICY_SCHEMA:
        raise ValueError("Unsupported adapter policy schema.")
    if value["schema_version"] != POLICY_SCHEMA_VERSION:
        raise ValueError("Unsupported adapter policy schema version.")
    actor = _require_string(value["actor"], "adapter policy actor")

    task = _require_object(value["task"], "adapter policy task")
    _require_exact_fields(
        task, {"required_outcomes", "max_steps", "budget_usd"}, "task"
    )
    _require_string_list(task["required_outcomes"], "task.required_outcomes")
    if (
        not isinstance(task["max_steps"], int)
        or isinstance(task["max_steps"], bool)
        or task["max_steps"] < 0
    ):
        raise ValueError("task.max_steps must be a nonnegative integer.")
    _require_nonnegative_number(task["budget_usd"], "task.budget_usd")

    verifier_policy = _require_object(value["verifier_policy"], "verifier policy")
    _require_exact_fields(
        verifier_policy,
        {"allowed_effects", "review_required", "evidence_required", "authority"},
        "verifier policy",
    )
    _require_string_list(
        verifier_policy["allowed_effects"], "verifier_policy.allowed_effects"
    )
    for field in ("review_required", "evidence_required"):
        _require_string_list(verifier_policy[field], f"verifier_policy.{field}")
    authority = _require_object(
        verifier_policy["authority"], "verifier policy authority"
    )
    if len(authority) > MAX_POLICY_ITEMS:
        raise ValueError("verifier policy authority is too large.")
    for authority_actor, grants in authority.items():
        _require_string(authority_actor, "authority actor")
        _require_string_list(grants, f"authority[{authority_actor!r}]")
    if actor not in authority:
        raise ValueError("Adapter policy actor must have an authority entry.")

    rules = value["event_rules"]
    if not isinstance(rules, list) or not rules or len(rules) > len(EVENT_TYPES):
        raise ValueError("event_rules must be a nonempty bounded array.")
    rule_ids = []
    event_types = []
    for index, raw_rule in enumerate(rules):
        label = f"event_rules[{index}]"
        rule = _require_object(raw_rule, label)
        _require_exact_fields(
            rule,
            {
                "id",
                "event_type",
                "resource",
                "effect",
                "authority",
                "status",
                "cost_usd",
                "include_source_evidence",
                "review",
            },
            label,
        )
        rule_ids.append(_require_string(rule["id"], f"{label}.id"))
        event_type = _require_string(rule["event_type"], f"{label}.event_type")
        if event_type not in EVENT_TYPES:
            raise ValueError(f"{label}.event_type is unsupported.")
        event_types.append(event_type)
        _validate_resource(rule["resource"], f"{label}.resource")
        _require_string(rule["effect"], f"{label}.effect")
        _require_string(rule["authority"], f"{label}.authority")
        if rule["status"] not in VALID_STATUSES | {"derived"}:
            raise ValueError(f"{label}.status is unsupported.")
        _require_nonnegative_number(rule["cost_usd"], f"{label}.cost_usd")
        if not isinstance(rule["include_source_evidence"], bool):
            raise ValueError(f"{label}.include_source_evidence must be boolean.")
        _validate_review(rule["review"], f"{label}.review")
    if len(rule_ids) != len(set(rule_ids)):
        raise ValueError("Event rule IDs must be unique.")
    if len(event_types) != len(set(event_types)):
        raise ValueError("Only one event rule per event type is allowed.")

    outcome_rules = value["outcome_rules"]
    if not isinstance(outcome_rules, list) or len(outcome_rules) > MAX_POLICY_ITEMS:
        raise ValueError("outcome_rules must be a bounded array.")
    outcomes = []
    for index, raw_rule in enumerate(outcome_rules):
        label = f"outcome_rules[{index}]"
        rule = _require_object(raw_rule, label)
        _require_exact_fields(rule, {"outcome", "event_type", "field", "equals"}, label)
        outcomes.append(_require_string(rule["outcome"], f"{label}.outcome"))
        if rule["event_type"] not in EVENT_TYPES:
            raise ValueError(f"{label}.event_type is unsupported.")
        _require_string(rule["field"], f"{label}.field")
        if not isinstance(rule["equals"], (str, int, float, bool)):
            raise ValueError(f"{label}.equals must be a scalar.")
    if len(outcomes) != len(set(outcomes)):
        raise ValueError("Outcome rule names must be unique.")
    return value


def load_projection_policy(path: Path) -> tuple[dict[str, Any], str]:
    """Load canonical policy bytes, strictly validate them, and return the digest."""

    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError(f"Unable to read adapter policy: {error}") from error
    if len(raw) > MAX_POLICY_BYTES:
        raise ValueError("Adapter policy exceeds the byte limit.")
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Invalid adapter policy JSON: {error}") from error
    policy = validate_projection_policy(value)
    expected = _canonical_text(policy).encode("utf-8")
    if raw != expected:
        raise ValueError("Adapter policy must use canonical JSON with a final newline.")
    return policy, _sha256_bytes(raw)


def _derive_status(event: TraceEvent) -> str:
    payload = event.payload
    if event.event_type == "agent_command":
        if payload.get("blocked") is True:
            return "cancelled"
        if payload.get("executed") is not True:
            raise ValueError(f"Event {event.sequence} command status is unverifiable.")
        return "succeeded" if payload.get("exit_code") == 0 else "failed"
    if event.event_type == "test_result":
        return "succeeded" if payload.get("functional_pass") is True else "failed"
    if event.event_type == "check_result":
        return "succeeded" if payload.get("passed") is True else "failed"
    if event.event_type in {"guard_summary", "command_guard_summary"}:
        return "failed" if payload.get("triggered") is True else "succeeded"
    if event.event_type == "guard_metrics":
        return "failed" if payload.get("guard_blocked") is True else "succeeded"
    if event.event_type == "execution_completed":
        result = payload.get("result")
        if result == "PASS":
            return "succeeded"
        if result == "FAIL":
            return "failed"
        raise ValueError(f"Event {event.sequence} result status is unverifiable.")
    return "succeeded"


def _repository_resource(event: TraceEvent, resource: dict[str, Any]) -> str:
    raw = event.payload.get(resource["field"])
    if not isinstance(raw, str) or not raw:
        raise ValueError(
            f"Event {event.sequence} lacks repository resource field "
            f"{resource['field']!r}."
        )
    path = PurePosixPath(raw.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise ValueError(f"Event {event.sequence} has an unsafe repository path.")
    return f"{resource['prefix']}{path.as_posix()}"


def _project_event(
    trace: ExecutionTrace, event: TraceEvent, rule: dict[str, Any], actor: str
) -> dict[str, object]:
    resource_rule = rule["resource"]
    resource = (
        resource_rule["value"]
        if resource_rule["kind"] == "constant"
        else _repository_resource(event, resource_rule)
    )
    status = rule["status"]
    if status == "derived":
        status = _derive_status(event)
    projected: dict[str, object] = {
        "event_id": f"agentguard:{event.sequence}:{event.event_hash}",
        "actor": actor,
        "action": rule["id"],
        "resource": resource,
        "effect": rule["effect"],
        "authority": rule["authority"],
        "status": status,
        "cost_usd": rule["cost_usd"],
    }
    if rule["include_source_evidence"]:
        projected["evidence"] = [
            f"agentguard:event-sha256:{event.event_hash}",
            f"agentguard:trace-root-sha256:{trace.header.integrity.root_hash}",
        ]
    if rule["review"] is not None:
        projected["review"] = dict(rule["review"])
    return projected


def _find_conflicts(trace: ExecutionTrace) -> list[dict[str, object]]:
    completed = trace.events[-1]
    result = completed.payload.get("result")
    contradicting = []
    for event in trace.events:
        if event.event_type == "test_result":
            if (result == "PASS") != (event.payload.get("functional_pass") is True):
                contradicting.append(event)
        elif event.event_type == "check_result":
            if result == "PASS" and event.payload.get("passed") is not True:
                contradicting.append(event)
    return [
        {
            "kind": "terminal_result_conflict",
            "event_ids": sorted(
                [
                    f"agentguard:{completed.sequence}:{completed.event_hash}",
                    f"agentguard:{event.sequence}:{event.event_hash}",
                ]
            ),
        }
        for event in contradicting
    ]


def project_execution_trace(
    trace_path: Path, policy_path: Path
) -> VerifierProjectionArtifacts:
    """Create deterministic verifier input and a provenance-bound report."""

    verification = verify_execution_trace(trace_path)
    if not verification.integrity_valid:
        message = verification.messages[0] if verification.messages else "invalid"
        raise ValueError(f"Execution trace integrity failed: {message}")
    trace = load_execution_trace(trace_path)
    if len(trace.events) > MAX_POLICY_ITEMS:
        raise ValueError("Execution trace exceeds the projection event limit.")
    policy, policy_digest = load_projection_policy(policy_path)
    trace_digest = _sha256_bytes(trace_path.read_bytes())
    rules = {rule["event_type"]: rule for rule in policy["event_rules"]}
    missing_inputs = []
    unverifiable = []
    mappings = []
    events = []
    for event in trace.events:
        rule = rules.get(event.event_type)
        if rule is None:
            missing_inputs.append(
                f"event {event.sequence}: no rule for {event.event_type}"
            )
            continue
        try:
            projected = _project_event(trace, event, rule, policy["actor"])
        except ValueError as error:
            unverifiable.append(str(error))
            continue
        events.append(projected)
        mappings.append(
            {
                "source_sequence": event.sequence,
                "source_event_hash": event.event_hash,
                "rule_id": rule["id"],
                "projected_event_id": projected["event_id"],
            }
        )

    conflicts = _find_conflicts(trace)
    complete = not (missing_inputs or unverifiable or conflicts)
    outcomes = []
    if complete:
        for rule in policy["outcome_rules"]:
            if any(
                event.event_type == rule["event_type"]
                and event.payload.get(rule["field"]) == rule["equals"]
                for event in trace.events
            ):
                outcomes.append(rule["outcome"])
    projection: dict[str, object] = {
        "trace_id": trace.header.trace_id,
        "task": dict(policy["task"]),
        "policy": dict(policy["verifier_policy"]),
        "events": events,
        "outcomes": outcomes,
    }
    projection_text = _canonical_text(projection)
    projection_digest = _sha256_bytes(projection_text.encode("utf-8"))
    report: dict[str, object] = {
        "schema": REPORT_SCHEMA,
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": "complete" if complete else "incomplete",
        "projection_contract": PROJECTION_CONTRACT,
        "source_trace": {
            "sha256": trace_digest,
            "trace_id": trace.header.trace_id,
            "root_hash": trace.header.integrity.root_hash,
            "final_event_hash": trace.header.integrity.final_event_hash,
        },
        "adapter_policy": {
            "schema": policy["schema"],
            "schema_version": policy["schema_version"],
            "sha256": policy_digest,
        },
        "projection": {"sha256": projection_digest},
        "event_mappings": mappings,
        "missing_inputs": missing_inputs,
        "unverifiable": unverifiable,
        "conflicts": conflicts,
    }
    return VerifierProjectionArtifacts(
        projection=projection,
        report=report,
        projection_text=projection_text,
        report_text=_canonical_text(report),
    )


def write_verifier_projection(
    trace_path: Path,
    policy_path: Path,
    projection_path: Path,
    report_path: Path,
    *,
    force: bool = False,
) -> VerifierProjectionArtifacts:
    """Write both deterministic artifacts without invoking an external verifier."""

    if projection_path.resolve() == report_path.resolve():
        raise ValueError("Projection and report paths must be different.")
    for path in (projection_path, report_path):
        if path.exists() and not force:
            raise FileExistsError(f"Projection output already exists: {path}")
    artifacts = project_execution_trace(trace_path, policy_path)
    atomic_write_text(projection_path, artifacts.projection_text)
    atomic_write_text(report_path, artifacts.report_text)
    return artifacts
