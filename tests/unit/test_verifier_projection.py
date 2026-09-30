import hashlib
import json
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest

from agentguard.containment.evidence import missing_containment_evidence
from agentguard.traces.execution import (
    TraceEvent,
    canonical_json,
    load_execution_trace,
    rehash_execution_trace,
    write_execution_trace,
)
from agentguard.traces.verifier_projection import (
    MAX_POLICY_BYTES,
    load_projection_policy,
    project_execution_trace,
)


FIXTURES = Path("tests/fixtures/verifier_projection")
SCHEMAS = Path("agentguard/schemas")


def _v3_trace(
    tmp_path: Path,
    name: str,
    *,
    include_containment: bool,
) -> Path:
    source = load_execution_trace(FIXTURES / f"{name}-trace-v2.jsonl")
    events = list(source.events)
    if include_containment:
        containment = TraceEvent(
            sequence=2,
            event_type="containment_evidence",
            payload=missing_containment_evidence(mode="local").to_dict(),
            previous_event_hash="",
            event_hash="",
        )
        events = [
            events[0],
            containment,
            *[replace(event, sequence=event.sequence + 1) for event in events[1:]],
        ]
    header = replace(
        source.header,
        schema_version=3,
        event_count=len(events),
    )
    trace = rehash_execution_trace(replace(source, header=header, events=events))
    path = tmp_path / f"{name}-trace-v3.jsonl"
    write_execution_trace(trace, path)
    return path


def _policy_with_containment(tmp_path: Path, name: str) -> Path:
    policy = json.loads(
        (FIXTURES / f"{name}-policy-v1.json").read_text(encoding="utf-8")
    )
    containment_rule = {
        "authority": "trace:observe",
        "cost_usd": 0,
        "effect": "observe",
        "event_type": "containment_evidence",
        "id": "containment-evidence-observed-v1",
        "include_source_evidence": True,
        "resource": {"kind": "constant", "value": "agentguard:containment"},
        "review": None,
        "status": "succeeded",
    }
    policy["event_rules"].insert(1, containment_rule)
    policy["task"]["max_steps"] = 7
    path = tmp_path / f"{name}-policy-with-containment-v1.json"
    path.write_text(canonical_json(policy) + "\n", encoding="utf-8")
    return path


@pytest.mark.parametrize("name", ["safe", "unsafe"])
def test_v3_without_optional_containment_is_byte_stable(
    tmp_path: Path,
    name: str,
) -> None:
    trace_path = _v3_trace(tmp_path, name, include_containment=False)
    policy_path = FIXTURES / f"{name}-policy-v1.json"

    first = project_execution_trace(trace_path, policy_path)
    second = project_execution_trace(trace_path, policy_path)

    assert first.projection_text.encode("utf-8") == second.projection_text.encode(
        "utf-8"
    )
    assert first.report_text.encode("utf-8") == second.report_text.encode("utf-8")
    assert first.report["status"] == "complete"
    assert first.report["source_trace"]["sha256"] == hashlib.sha256(
        trace_path.read_bytes()
    ).hexdigest()


@pytest.mark.parametrize("name", ["safe", "unsafe"])
def test_supported_v3_containment_event_is_byte_stable(
    tmp_path: Path,
    name: str,
) -> None:
    trace_path = _v3_trace(tmp_path, name, include_containment=True)
    policy_path = _policy_with_containment(tmp_path, name)

    first = project_execution_trace(trace_path, policy_path)
    second = project_execution_trace(trace_path, policy_path)

    assert first.projection_text == second.projection_text
    assert first.report_text == second.report_text
    assert first.report["status"] == "complete"
    containment = first.projection["events"][1]
    assert containment["action"] == "containment-evidence-observed-v1"
    assert containment["resource"] == "agentguard:containment"
    assert containment["effect"] == "observe"


def test_unsupported_v3_containment_event_is_explicit_and_byte_stable(
    tmp_path: Path,
) -> None:
    trace_path = _v3_trace(tmp_path, "safe", include_containment=True)
    policy_path = FIXTURES / "safe-policy-v1.json"

    first = project_execution_trace(trace_path, policy_path)
    second = project_execution_trace(trace_path, policy_path)

    assert first.projection_text == second.projection_text
    assert first.report_text == second.report_text
    assert first.report["status"] == "incomplete"
    assert first.report["missing_inputs"] == [
        "event 2: unsupported projection event containment_evidence (no rule)"
    ]
    assert first.projection["outcomes"] == []


def test_containment_derived_status_is_rejected_as_unverifiable(
    tmp_path: Path,
) -> None:
    trace_path = _v3_trace(tmp_path, "safe", include_containment=True)
    policy_path = _policy_with_containment(tmp_path, "safe")
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["event_rules"][1]["status"] = "derived"
    policy_path.write_text(canonical_json(policy) + "\n", encoding="utf-8")

    artifacts = project_execution_trace(trace_path, policy_path)

    assert artifacts.report["status"] == "incomplete"
    assert artifacts.report["unverifiable"] == [
        "Event 2 containment evidence requires an explicit projection status."
    ]


@pytest.mark.parametrize("name", ["safe", "unsafe"])
def test_artifact_contracts_match_checked_in_schemas(name: str) -> None:
    policy = json.loads(
        (FIXTURES / f"{name}-policy-v1.json").read_text(encoding="utf-8")
    )
    schema = json.loads(
        (SCHEMAS / "verifier-projection-policy-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(schema).validate(policy)


def test_projection_uses_full_hashes_and_never_copies_raw_commands(
    tmp_path: Path,
) -> None:
    trace_path = _v3_trace(tmp_path, "unsafe", include_containment=False)
    trace = load_execution_trace(trace_path)
    artifacts = project_execution_trace(trace_path, FIXTURES / "unsafe-policy-v1.json")

    command_event = next(
        event for event in trace.events if event.event_type == "agent_command"
    )
    projected_command = artifacts.projection["events"][1]
    assert projected_command["event_id"] == (
        f"agentguard:{command_event.sequence}:{command_event.event_hash}"
    )
    assert command_event.payload["command"] not in artifacts.projection_text
    assert "command_text" not in artifacts.projection_text


def test_projection_preserves_portable_repository_resources(tmp_path: Path) -> None:
    trace_path = _v3_trace(tmp_path, "safe", include_containment=False)
    artifacts = project_execution_trace(trace_path, FIXTURES / "safe-policy-v1.json")

    file_event = next(
        event for event in artifacts.projection["events"]
        if event["action"] == "file-change-v1"
    )
    assert file_event["resource"] == "repository:src/widget.py"
    assert "/Users/" not in artifacts.projection_text
    assert "/home/" not in artifacts.projection_text


def test_projection_does_not_change_agentguard_scores_or_trace_bytes(
    tmp_path: Path,
) -> None:
    trace_path = _v3_trace(tmp_path, "safe", include_containment=False)
    before_bytes = trace_path.read_bytes()
    before = load_execution_trace(trace_path)
    before_score = before.events[-1].payload["score"]
    before_contributions = [
        event.payload["score_contribution"]
        for event in before.events
        if event.event_type == "check_result"
    ]

    project_execution_trace(trace_path, FIXTURES / "safe-policy-v1.json")
    after = load_execution_trace(trace_path)

    assert trace_path.read_bytes() == before_bytes
    assert after.events[-1].payload["score"] == before_score
    assert [
        event.payload["score_contribution"]
        for event in after.events
        if event.event_type == "check_result"
    ] == before_contributions


def test_policy_requires_exact_fields_without_echoing_untrusted_names(
    tmp_path: Path,
) -> None:
    source = FIXTURES / "safe-policy-v1.json"
    policy = json.loads(source.read_text(encoding="utf-8"))
    secret_like_field = "token-super-secret-value"
    policy[secret_like_field] = True
    path = tmp_path / "unknown.json"
    path.write_text(canonical_json(policy) + "\n", encoding="utf-8")

    with pytest.raises(ValueError) as error:
        load_projection_policy(path)

    assert secret_like_field not in str(error.value)
    assert "unknown=1" in str(error.value)


def test_policy_json_diagnostics_do_not_echo_untrusted_content(
    tmp_path: Path,
) -> None:
    secret_like_text = "token-super-secret-value"
    path = tmp_path / "malformed.json"
    path.write_text('{"broken":"' + secret_like_text, encoding="utf-8")

    with pytest.raises(ValueError) as error:
        load_projection_policy(path)

    assert str(error.value) == "Invalid adapter policy JSON."
    assert secret_like_text not in str(error.value)


def test_policy_read_is_bounded(tmp_path: Path) -> None:
    path = tmp_path / "oversized.json"
    path.write_bytes(b" " * (MAX_POLICY_BYTES + 1))

    with pytest.raises(ValueError, match="byte limit"):
        load_projection_policy(path)


def test_missing_mapping_fails_closed_in_report(tmp_path: Path) -> None:
    trace_path = _v3_trace(tmp_path, "safe", include_containment=False)
    source = FIXTURES / "safe-policy-v1.json"
    policy = json.loads(source.read_text(encoding="utf-8"))
    policy["event_rules"] = [
        rule for rule in policy["event_rules"] if rule["event_type"] != "file_change"
    ]
    policy_path = tmp_path / "missing-rule.json"
    policy_path.write_text(canonical_json(policy) + "\n", encoding="utf-8")

    artifacts = project_execution_trace(trace_path, policy_path)

    assert artifacts.report["status"] == "incomplete"
    assert artifacts.report["missing_inputs"] == [
        "event 3: unsupported projection event file_change (no rule)"
    ]
    assert artifacts.projection["outcomes"] == []


def test_conflicting_source_facts_preserve_both_full_hashes(
    tmp_path: Path,
) -> None:
    trace_path = _v3_trace(tmp_path, "safe", include_containment=False)
    source = load_execution_trace(trace_path)
    events = []
    for event in source.events:
        if event.event_type == "check_result":
            events.append(
                replace(
                    event,
                    payload={
                        **event.payload,
                        "passed": False,
                        "score_contribution": -20,
                    },
                )
            )
        else:
            events.append(event)
    conflicted = rehash_execution_trace(replace(source, events=events))
    conflicted_path = tmp_path / "conflicted.jsonl"
    write_execution_trace(conflicted, conflicted_path)

    artifacts = project_execution_trace(
        conflicted_path,
        FIXTURES / "safe-policy-v1.json",
    )

    assert artifacts.report["status"] == "incomplete"
    assert artifacts.projection["outcomes"] == []
    conflict = artifacts.report["conflicts"][0]
    assert conflict["kind"] == "terminal_result_conflict"
    assert len(conflict["event_ids"]) == 2
    assert all(
        len(event_id.rsplit(":", 1)[-1]) == 64 for event_id in conflict["event_ids"]
    )


def test_malformed_trace_is_rejected_before_projection(
    tmp_path: Path,
) -> None:
    trace_path = _v3_trace(tmp_path, "safe", include_containment=False)
    malformed = tmp_path / "malformed.jsonl"
    malformed.write_bytes(
        trace_path.read_bytes().replace(b"synthetic-agent", b"other-agent", 1)
    )

    with pytest.raises(ValueError, match="integrity failed"):
        project_execution_trace(malformed, FIXTURES / "safe-policy-v1.json")
