import json
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest

from agentguard.traces.execution import (
    canonical_json,
    load_execution_trace,
    rehash_execution_trace,
    write_execution_trace,
)
from agentguard.traces.verifier_projection import (
    load_projection_policy,
    project_execution_trace,
)


FIXTURES = Path("tests/fixtures/verifier_projection")
SCHEMAS = Path("agentguard/schemas")


@pytest.mark.parametrize("name", ["safe", "unsafe"])
def test_seeded_projections_and_reports_are_byte_stable(name: str) -> None:
    trace_path = FIXTURES / f"{name}-trace-v2.jsonl"
    policy_path = FIXTURES / f"{name}-policy-v1.json"

    first = project_execution_trace(trace_path, policy_path)
    second = project_execution_trace(trace_path, policy_path)

    assert first.projection_text == second.projection_text
    assert first.report_text == second.report_text
    assert first.projection_text == (
        FIXTURES / f"{name}-expected-projection-v1.json"
    ).read_text(encoding="utf-8")
    assert first.report_text == (
        FIXTURES / f"{name}-expected-report-v1.json"
    ).read_text(encoding="utf-8")
    assert first.report["status"] == "complete"


@pytest.mark.parametrize("name", ["safe", "unsafe"])
def test_seeded_artifacts_match_checked_in_versioned_schemas(name: str) -> None:
    policy = json.loads(
        (FIXTURES / f"{name}-policy-v1.json").read_text(encoding="utf-8")
    )
    projection = json.loads(
        (FIXTURES / f"{name}-expected-projection-v1.json").read_text(encoding="utf-8")
    )
    report = json.loads(
        (FIXTURES / f"{name}-expected-report-v1.json").read_text(encoding="utf-8")
    )

    for value, schema_name in (
        (policy, "verifier-projection-policy-v1.schema.json"),
        (projection, "verifier-projection-v1.schema.json"),
        (report, "verifier-projection-report-v1.schema.json"),
    ):
        schema = json.loads((SCHEMAS / schema_name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(value)


def test_projection_uses_full_hashes_and_never_copies_raw_commands() -> None:
    trace_path = FIXTURES / "unsafe-trace-v2.jsonl"
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


def test_projection_does_not_change_agentguard_scores_or_trace_bytes() -> None:
    trace_path = FIXTURES / "safe-trace-v2.jsonl"
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


def test_policy_requires_exact_fields_and_canonical_bytes(tmp_path: Path) -> None:
    source = FIXTURES / "safe-policy-v1.json"
    policy = json.loads(source.read_text(encoding="utf-8"))
    policy["unexpected"] = True
    unknown_path = tmp_path / "unknown.json"
    unknown_path.write_text(canonical_json(policy) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="unknown unexpected"):
        load_projection_policy(unknown_path)

    pretty_path = tmp_path / "pretty.json"
    pretty_path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown unexpected"):
        load_projection_policy(pretty_path)

    valid_policy = json.loads(source.read_text(encoding="utf-8"))
    pretty_path.write_text(json.dumps(valid_policy, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="canonical JSON"):
        load_projection_policy(pretty_path)


def test_missing_mapping_fails_closed_in_report(tmp_path: Path) -> None:
    source = FIXTURES / "safe-policy-v1.json"
    policy = json.loads(source.read_text(encoding="utf-8"))
    policy["event_rules"] = [
        rule for rule in policy["event_rules"] if rule["event_type"] != "file_change"
    ]
    policy_path = tmp_path / "missing-rule.json"
    policy_path.write_text(canonical_json(policy) + "\n", encoding="utf-8")

    artifacts = project_execution_trace(FIXTURES / "safe-trace-v2.jsonl", policy_path)

    assert artifacts.report["status"] == "incomplete"
    assert artifacts.report["missing_inputs"] == ["event 3: no rule for file_change"]
    assert artifacts.projection["outcomes"] == []


def test_conflicting_source_facts_preserve_both_full_hashes(
    tmp_path: Path,
) -> None:
    source = load_execution_trace(FIXTURES / "safe-trace-v2.jsonl")
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
    trace_path = tmp_path / "conflicted.jsonl"
    write_execution_trace(conflicted, trace_path)

    artifacts = project_execution_trace(trace_path, FIXTURES / "safe-policy-v1.json")

    assert artifacts.report["status"] == "incomplete"
    assert artifacts.projection["outcomes"] == []
    conflict = artifacts.report["conflicts"][0]
    assert conflict["kind"] == "terminal_result_conflict"
    assert len(conflict["event_ids"]) == 2
    assert all(
        len(event_id.rsplit(":", 1)[-1]) == 64 for event_id in conflict["event_ids"]
    )


def test_malformed_trace_is_rejected_before_projection(tmp_path: Path) -> None:
    source = FIXTURES / "safe-trace-v2.jsonl"
    malformed = tmp_path / "malformed.jsonl"
    malformed.write_bytes(
        source.read_bytes().replace(b"synthetic-agent", b"other-agent", 1)
    )

    with pytest.raises(ValueError, match="integrity failed"):
        project_execution_trace(malformed, FIXTURES / "safe-policy-v1.json")
