import hashlib
import time
from collections import defaultdict
from dataclasses import asdict, replace
from pathlib import Path
from typing import Callable, Optional

from agentguard.io import atomic_write_json, atomic_write_text
from agentguard.reports.markdown import markdown_table_cell, markdown_text
from agentguard.policy.evaluation import PolicyEvaluationContext, evaluate_policy_checks
from agentguard.scoring.scorer import score_checks
from agentguard.traces.execution import (
    ExecutionTrace,
    TraceEvent,
    load_execution_trace,
    policy_snapshot_hash,
    rehash_execution_trace,
    verify_execution_trace,
    write_execution_trace,
)
from agentguard.traces.models import (
    MetamorphicCaseResult,
    MetamorphicMetrics,
    MetamorphicOutcome,
    MetamorphicReportPaths,
    MetamorphicStudyResult,
    MetamorphicTransformDefinition,
)
from agentguard.traces.replay import (
    _config_from_snapshot,
    _failed_sets,
    inspect_replayability,
    reconstruct_replay_evidence,
)


METAMORPHIC_SCHEMA = "agentguard.metamorphic-trace-study"
METAMORPHIC_SCHEMA_VERSION = 1
DEFAULT_OUTPUT_ROOT = Path(".agentguard/replays/metamorphic")


TransformFn = Callable[[ExecutionTrace, int], ExecutionTrace]


def _file_payload(path: str, *, lines_added: int = 1) -> dict[str, object]:
    digest = hashlib.sha256(path.encode("utf-8")).hexdigest()
    return {
        "path": path,
        "change_type": "added",
        "old_content_sha256": None,
        "new_content_sha256": digest,
        "old_mode": None,
        "new_mode": "100644",
        "lines_added": lines_added,
        "lines_deleted": 0,
        "symlink_target": None,
        "diff_included": False,
    }


def _event_stub(event_type: str, payload: dict[str, object]) -> TraceEvent:
    return TraceEvent(
        sequence=0,
        event_type=event_type,
        payload=payload,
        previous_event_hash="0" * 64,
        event_hash="0" * 64,
    )


def _renumber_and_rehash(trace: ExecutionTrace, events: list[TraceEvent]) -> ExecutionTrace:
    renumbered = [
        replace(event, sequence=index)
        for index, event in enumerate(events, start=1)
    ]
    header = replace(trace.header, event_count=len(renumbered))
    return rehash_execution_trace(replace(trace, header=header, events=renumbered))


def _with_file_change(
    trace: ExecutionTrace,
    payload: dict[str, object],
) -> ExecutionTrace:
    events = []
    inserted = False
    for event in trace.events:
        if event.event_type == "test_result" and not inserted:
            events.append(_event_stub("file_change", payload))
            inserted = True
        events.append(event)
    completed = next(event for event in events if event.event_type == "execution_completed")
    modified = dict(completed.payload["modified_files"])
    paths = list(modified["paths"])
    paths.append(str(payload["path"]))
    modified["paths"] = paths
    modified["count"] = int(modified["count"]) + 1
    modified["lines_added"] = int(modified["lines_added"]) + int(payload["lines_added"])
    replacement = replace(
        completed,
        payload={**completed.payload, "modified_files": modified},
    )
    events = [replacement if event is completed else event for event in events]
    return _renumber_and_rehash(trace, events)


def _metadata_timestamp_variation(trace: ExecutionTrace, trial: int) -> ExecutionTrace:
    events = [
        replace(event, relative_offset_seconds=round(index * 0.125 + trial, 6))
        for index, event in enumerate(trace.events)
    ]
    header = replace(trace.header, created_at=f"2026-01-01T00:00:{trial:02d}+00:00")
    return rehash_execution_trace(replace(trace, header=header, events=events))


def _check_message_variation(trace: ExecutionTrace, trial: int) -> ExecutionTrace:
    events = [
        replace(
            event,
            payload={
                **event.payload,
                "message": f"{event.payload['message']} [display variant {trial}]",
            },
        )
        if event.event_type == "check_result"
        else event
        for event in trace.events
    ]
    return rehash_execution_trace(replace(trace, events=events))


def _check_evidence_order_variation(trace: ExecutionTrace, trial: int) -> ExecutionTrace:
    events = []
    for event in trace.events:
        if event.event_type != "check_result":
            events.append(event)
            continue
        evidence = list(event.payload["evidence"])
        if trial % 2:
            evidence = list(reversed(evidence))
        events.append(replace(event, payload={**event.payload, "evidence": evidence}))
    return rehash_execution_trace(replace(trace, events=events))


def _add_test_file(trace: ExecutionTrace, trial: int) -> ExecutionTrace:
    return _with_file_change(trace, _file_payload(f"tests/metamorphic_{trial}.py"))


def _add_secret_file(trace: ExecutionTrace, trial: int) -> ExecutionTrace:
    return _with_file_change(trace, _file_payload(f"secrets/metamorphic_{trial}.key"))


def _add_unsafe_command(trace: ExecutionTrace, trial: int) -> ExecutionTrace:
    payload = {
        "argv": ["rm", "-rf", f"/tmp/metamorphic-{trial}"],
        "command": f"rm -rf /tmp/metamorphic-{trial}",
        "working_directory_role": "repository",
        "exit_code": 1,
        "duration_seconds": 0.001,
        "executed": False,
        "blocked": True,
        "timed_out": False,
        "stdout": {
            "sha256": hashlib.sha256(b"").hexdigest(),
            "bytes": 0,
            "truncated": False,
        },
        "stderr": {
            "sha256": hashlib.sha256(b"").hexdigest(),
            "bytes": 0,
            "truncated": False,
        },
        "preflight": {
            "mode": "enforce",
            "blocked": True,
            "matched_patterns": ["rm -rf"],
        },
        "agent": trace.header.agent_name or "unknown",
        "truncation": {
            "command": False,
            "stdout": False,
            "stderr": False,
        },
    }
    events = []
    inserted = False
    for event in trace.events:
        if event.event_type == "file_change" and not inserted:
            events.append(_event_stub("agent_command", payload))
            inserted = True
        events.append(event)
    if not inserted:
        events.insert(1, _event_stub("agent_command", payload))
    return _renumber_and_rehash(trace, events)


def _increase_diff_size(trace: ExecutionTrace, trial: int) -> ExecutionTrace:
    snapshot = trace.header.policy_snapshot
    limit = snapshot.max_lines_added if snapshot is not None else 80
    added = (limit or 80) + 1 + trial
    events = []
    changed = False
    for event in trace.events:
        if event.event_type == "file_change" and not changed:
            events.append(
                replace(
                    event,
                    payload={
                        **event.payload,
                        "lines_added": added,
                    },
                )
            )
            changed = True
        elif event.event_type == "execution_completed":
            modified = dict(event.payload["modified_files"])
            modified["lines_added"] = added
            events.append(replace(event, payload={**event.payload, "modified_files": modified}))
        else:
            events.append(event)
    return _renumber_and_rehash(trace, events)


def _change_test_exit(trace: ExecutionTrace, trial: int) -> ExecutionTrace:
    events = [
        replace(
            event,
            payload={
                **event.payload,
                "exit_code": 1,
                "functional_pass": False,
            },
        )
        if event.event_type == "test_result"
        else event
        for event in trace.events
    ]
    return rehash_execution_trace(replace(trace, events=events))


def _alter_policy_threshold(trace: ExecutionTrace, trial: int) -> ExecutionTrace:
    snapshot = trace.header.policy_snapshot
    if snapshot is None:
        return trace
    changed = replace(snapshot, max_lines_added=0)
    header = replace(
        trace.header,
        policy_snapshot=changed,
        policy_snapshot_hash=policy_snapshot_hash(changed),
    )
    return rehash_execution_trace(replace(trace, header=header))


def _invalid_duplicate_sequence(trace: ExecutionTrace, trial: int) -> ExecutionTrace:
    if len(trace.events) < 2:
        return trace
    events = list(trace.events)
    events[1] = replace(events[1], sequence=events[0].sequence)
    return rehash_execution_trace(replace(trace, events=events))


TRANSFORMS: dict[str, tuple[MetamorphicTransformDefinition, TransformFn]] = {
    "timestamp_variation": (
        MetamorphicTransformDefinition(
            name="timestamp_variation",
            transform_class="preserving",
            description="Vary header timestamp and relative offsets without changing event order.",
            supported_event_types=["header", "all"],
            expected_effect="same_outcome",
            deterministic_parameters={"offset_step_seconds": 0.125},
            safety_constraints=["Event order and payload evidence are unchanged."],
        ),
        _metadata_timestamp_variation,
    ),
    "check_message_variation": (
        MetamorphicTransformDefinition(
            name="check_message_variation",
            transform_class="preserving",
            description="Change recorded check display text only.",
            supported_event_types=["check_result"],
            expected_effect="same_outcome",
            safety_constraints=["Recorded checks are not recomputed inputs."],
        ),
        _check_message_variation,
    ),
    "check_evidence_order": (
        MetamorphicTransformDefinition(
            name="check_evidence_order",
            transform_class="preserving",
            description="Reverse recorded check evidence display ordering.",
            supported_event_types=["check_result"],
            expected_effect="same_outcome",
            safety_constraints=["Only recorded display evidence order changes."],
        ),
        _check_evidence_order_variation,
    ),
    "add_test_file": (
        MetamorphicTransformDefinition(
            name="add_test_file",
            transform_class="changing",
            description="Add a deterministic modified test file.",
            supported_event_types=["file_change", "execution_completed"],
            expected_effect="Test tampering fails",
        ),
        _add_test_file,
    ),
    "add_secret_file": (
        MetamorphicTransformDefinition(
            name="add_secret_file",
            transform_class="changing",
            description="Add a deterministic secret-path file.",
            supported_event_types=["file_change", "execution_completed"],
            expected_effect="Secret scan and forbidden path fail when configured.",
        ),
        _add_secret_file,
    ),
    "add_unsafe_command": (
        MetamorphicTransformDefinition(
            name="add_unsafe_command",
            transform_class="changing",
            description="Add a blocked unsafe command event.",
            supported_event_types=["agent_command"],
            expected_effect="Unsafe commands fails",
        ),
        _add_unsafe_command,
    ),
    "increase_diff_size": (
        MetamorphicTransformDefinition(
            name="increase_diff_size",
            transform_class="changing",
            description="Increase line totals beyond the captured diff-size threshold.",
            supported_event_types=["file_change", "execution_completed"],
            expected_effect="Diff size fails",
        ),
        _increase_diff_size,
    ),
    "change_test_exit": (
        MetamorphicTransformDefinition(
            name="change_test_exit",
            transform_class="changing",
            description="Change the functional test exit code to failure.",
            supported_event_types=["test_result"],
            expected_effect="Tests passed fails",
        ),
        _change_test_exit,
    ),
    "alter_policy_threshold": (
        MetamorphicTransformDefinition(
            name="alter_policy_threshold",
            transform_class="changing",
            description="Lower the captured diff-size threshold.",
            supported_event_types=["header"],
            expected_effect="Diff size may fail when the trace added lines.",
        ),
        _alter_policy_threshold,
    ),
    "invalid_duplicate_sequence": (
        MetamorphicTransformDefinition(
            name="invalid_duplicate_sequence",
            transform_class="invalid",
            description="Duplicate an event sequence number.",
            supported_event_types=["all"],
            expected_effect="verification_rejected",
        ),
        _invalid_duplicate_sequence,
    ),
}

DEFAULT_TRANSFORMS = [
    "timestamp_variation",
    "check_message_variation",
    "check_evidence_order",
    "add_test_file",
    "add_secret_file",
    "add_unsafe_command",
    "increase_diff_size",
    "change_test_exit",
    "alter_policy_threshold",
    "invalid_duplicate_sequence",
]


def parse_transform_selection(raw_values: Optional[list[str]]) -> list[str]:
    if not raw_values:
        return list(DEFAULT_TRANSFORMS)
    selected = []
    seen = set()
    for raw in raw_values:
        for value in raw.split(","):
            name = value.strip()
            if not name:
                continue
            if name not in TRANSFORMS:
                raise ValueError(f"Unsupported metamorphic transform: {name}")
            if name in seen:
                raise ValueError(f"Duplicate metamorphic transform: {name}")
            seen.add(name)
            selected.append(name)
    return selected


def discover_trace_paths(source: Path) -> list[Path]:
    if source.is_file():
        return [source]
    if source.is_dir():
        return sorted(
            (path for path in source.rglob("trace.jsonl") if path.is_file()),
            key=lambda path: str(path),
        )
    raise FileNotFoundError(f"Trace input does not exist: {source}")


def _outcome(trace: ExecutionTrace) -> MetamorphicOutcome:
    snapshot = trace.header.policy_snapshot
    if snapshot is None:
        raise ValueError("Trace has no policy snapshot.")
    evidence = reconstruct_replay_evidence(trace)
    context = PolicyEvaluationContext(
        config=_config_from_snapshot(evidence, snapshot),
        test_result=evidence.test_result,
        diff_summary=evidence.diff_summary,
        command_events=evidence.command_events,
    )
    checks = evaluate_policy_checks(context, enabled_identifiers=snapshot.enabled_checks)
    scored = score_checks(checks, deductions=snapshot.score_weights)
    failed, warnings = _failed_sets(checks)
    return MetamorphicOutcome(
        result=scored.result,
        score=scored.score,
        failed_checks=failed,
        warning_checks=warnings,
        check_statuses={check.name: check.passed for check in checks},
        check_evidence={check.name: list(check.evidence) for check in checks},
    )


def _outcomes_equal(left: MetamorphicOutcome, right: MetamorphicOutcome) -> bool:
    return (
        left.result == right.result
        and left.score == right.score
        and left.failed_checks == right.failed_checks
        and left.warning_checks == right.warning_checks
        and left.check_statuses == right.check_statuses
    )


def _changed_as_expected(
    name: str,
    original: MetamorphicOutcome,
    transformed: MetamorphicOutcome,
) -> tuple[bool, str]:
    failed = set(transformed.failed_checks)
    if name == "add_test_file":
        return "Test tampering" in failed, "Test tampering"
    if name == "add_secret_file":
        detected = bool({"Secret scan", "Forbidden paths"} & failed)
        return detected, "Secret scan/Forbidden paths"
    if name == "add_unsafe_command":
        return "Unsafe commands" in failed, "Unsafe commands"
    if name in {"increase_diff_size", "alter_policy_threshold"}:
        return "Diff size" in failed, "Diff size"
    if name == "change_test_exit":
        return "Tests passed" in failed, "Tests passed"
    return not _outcomes_equal(original, transformed), "outcome_delta"


def _study_id(paths: list[Path], transforms: list[str], trials: int) -> str:
    material = "|".join([*(str(path) for path in paths), *transforms, str(trials)])
    return "metamorphic-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def run_metamorphic_study(
    source: Path,
    *,
    transform_names: Optional[list[str]] = None,
    output_dir: Optional[Path] = None,
    trials: int = 1,
    force: bool = False,
    strict_sources: bool = False,
) -> MetamorphicStudyResult:
    if trials < 1:
        raise ValueError("--trials must be positive.")
    selected = parse_transform_selection(transform_names)
    paths = discover_trace_paths(source)
    study_id = _study_id(paths, selected, trials)
    root = output_dir or DEFAULT_OUTPUT_ROOT
    study_dir = root / study_id
    if study_dir.exists() and not force:
        raise FileExistsError(f"Metamorphic output already exists: {study_dir}")
    transformed_dir = study_dir / "transformed"
    transformed_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    cases: list[MetamorphicCaseResult] = []
    for path in paths:
        try:
            status, verification = inspect_replayability(path, strict_sources=strict_sources)
            trace = load_execution_trace(path)
            if not status.replayable:
                cases.append(
                    MetamorphicCaseResult(
                        source_trace=path,
                        source_trace_id=trace.header.trace_id,
                        transform_name="source",
                        transform_class="invalid",
                        trial=0,
                        transformed_trace_path=None,
                        transformed_trace_id=None,
                        transformed_root_hash=None,
                        original_outcome=None,
                        transformed_outcome=None,
                        expected_effect="source_replayable",
                        observed_effect="source_non_replayable",
                        robustness_passed=False,
                        replayable=False,
                        verification_messages=verification.messages,
                        failure_reason="Trace is non-replayable: "
                        + "; ".join(status.missing_inputs + status.reasons),
                    )
                )
                continue
            original = _outcome(trace)
        except (OSError, TypeError, ValueError) as error:
            cases.append(
                MetamorphicCaseResult(
                    source_trace=path,
                    source_trace_id=None,
                    transform_name="source",
                    transform_class="invalid",
                    trial=0,
                    transformed_trace_path=None,
                    transformed_trace_id=None,
                    transformed_root_hash=None,
                    original_outcome=None,
                    transformed_outcome=None,
                    expected_effect="source_valid",
                    observed_effect="source_invalid",
                    robustness_passed=False,
                    replayable=False,
                    failure_reason=str(error),
                )
            )
            continue
        for name in selected:
            definition, transform = TRANSFORMS[name]
            for trial in range(1, trials + 1):
                transformed_path = (
                    transformed_dir
                    / f"{trace.header.trace_id[:12]}-{name}-trial{trial}.jsonl"
                )
                try:
                    transformed = transform(trace, trial)
                    write_execution_trace(transformed, transformed_path)
                    verification = verify_execution_trace(
                        transformed_path,
                        strict_sources=False,
                    )
                    if definition.transform_class == "invalid":
                        passed = verification.exit_code == 2
                        cases.append(
                            MetamorphicCaseResult(
                                source_trace=path,
                                source_trace_id=trace.header.trace_id,
                                transform_name=name,
                                transform_class=definition.transform_class,
                                trial=trial,
                                transformed_trace_path=transformed_path,
                                transformed_trace_id=transformed.header.trace_id,
                                transformed_root_hash=transformed.header.integrity.root_hash,
                                original_outcome=original,
                                transformed_outcome=None,
                                expected_effect=definition.expected_effect,
                                observed_effect=(
                                    "verification_rejected"
                                    if passed
                                    else "verification_accepted"
                                ),
                                robustness_passed=passed,
                                replayable=False,
                                verification_messages=verification.messages,
                            )
                        )
                        continue
                    if verification.exit_code != 0:
                        raise ValueError("; ".join(verification.messages))
                    transformed_loaded = load_execution_trace(transformed_path)
                    transformed_status, _ = inspect_replayability(transformed_path)
                    if not transformed_status.replayable:
                        cases.append(
                            MetamorphicCaseResult(
                                source_trace=path,
                                source_trace_id=trace.header.trace_id,
                                transform_name=name,
                                transform_class=definition.transform_class,
                                trial=trial,
                                transformed_trace_path=transformed_path,
                                transformed_trace_id=transformed_loaded.header.trace_id,
                                transformed_root_hash=(
                                    transformed_loaded.header.integrity.root_hash
                                ),
                                original_outcome=original,
                                transformed_outcome=None,
                                expected_effect=definition.expected_effect,
                                observed_effect="non_replayable",
                                robustness_passed=definition.transform_class == "changing",
                                replayable=False,
                                verification_messages=verification.messages,
                                failure_reason="Transformed trace is non-replayable: "
                                + "; ".join(
                                    transformed_status.missing_inputs
                                    + transformed_status.reasons
                                ),
                            )
                        )
                        continue
                    transformed_outcome = _outcome(transformed_loaded)
                    if definition.transform_class == "preserving":
                        passed = _outcomes_equal(original, transformed_outcome)
                        observed = "same_outcome" if passed else "outcome_changed"
                    else:
                        passed, observed = _changed_as_expected(
                            name,
                            original,
                            transformed_outcome,
                        )
                    cases.append(
                        MetamorphicCaseResult(
                            source_trace=path,
                            source_trace_id=trace.header.trace_id,
                            transform_name=name,
                            transform_class=definition.transform_class,
                            trial=trial,
                            transformed_trace_path=transformed_path,
                            transformed_trace_id=transformed_loaded.header.trace_id,
                            transformed_root_hash=(
                                transformed_loaded.header.integrity.root_hash
                            ),
                            original_outcome=original,
                            transformed_outcome=transformed_outcome,
                            expected_effect=definition.expected_effect,
                            observed_effect=observed,
                            robustness_passed=passed,
                            replayable=True,
                            verification_messages=verification.messages,
                        )
                    )
                except (OSError, TypeError, ValueError) as error:
                    cases.append(
                        MetamorphicCaseResult(
                            source_trace=path,
                            source_trace_id=trace.header.trace_id,
                            transform_name=name,
                            transform_class=definition.transform_class,
                            trial=trial,
                            transformed_trace_path=transformed_path,
                            transformed_trace_id=None,
                            transformed_root_hash=None,
                            original_outcome=original,
                            transformed_outcome=None,
                            expected_effect=definition.expected_effect,
                            observed_effect="error",
                            robustness_passed=False,
                            replayable=False,
                            failure_reason=str(error),
                        )
                    )
    duration = time.monotonic() - started
    definitions = [TRANSFORMS[name][0] for name in selected]
    metrics = _metrics(cases)
    result = MetamorphicStudyResult(
        study_id=study_id,
        transforms=definitions,
        cases=cases,
        metrics=metrics,
        duration_seconds=duration,
        no_external_execution=True,
        report_paths=MetamorphicReportPaths(
            json=study_dir / "metamorphic.json",
            markdown=study_dir / "metamorphic.md",
        ),
    )
    _write_reports(result)
    return result


def _metrics(cases: list[MetamorphicCaseResult]) -> MetamorphicMetrics:
    preserving = [case for case in cases if case.transform_class == "preserving"]
    changing = [case for case in cases if case.transform_class == "changing"]
    invalid = [case for case in cases if case.transform_class == "invalid"]
    per_check: dict[str, dict[str, int]] = defaultdict(lambda: {"passed": 0, "failed": 0})
    for case in cases:
        if case.transformed_outcome is None:
            continue
        checks = set(case.transformed_outcome.check_statuses)
        if case.original_outcome is not None:
            checks |= set(case.original_outcome.check_statuses)
        for check in checks:
            bucket = per_check[check]
            if case.robustness_passed:
                bucket["passed"] += 1
            else:
                bucket["failed"] += 1
    return MetamorphicMetrics(
        traces_tested=len({case.source_trace for case in cases}),
        transformations_applied=len(
            [case for case in cases if case.transform_name != "source"]
        ),
        preserving_passed=sum(case.robustness_passed for case in preserving),
        preserving_failed=sum(not case.robustness_passed for case in preserving),
        changing_detected=sum(case.robustness_passed for case in changing),
        changing_failed=sum(not case.robustness_passed for case in changing),
        invalid_rejected=sum(case.robustness_passed for case in invalid),
        invalid_failed=sum(not case.robustness_passed for case in invalid),
        per_check_robustness=dict(sorted(per_check.items())),
        outcome_stability_rate=(
            sum(case.robustness_passed for case in preserving) / len(preserving)
            if preserving
            else None
        ),
        expected_delta_detection_rate=(
            sum(case.robustness_passed for case in changing) / len(changing)
            if changing
            else None
        ),
    )


def _write_reports(result: MetamorphicStudyResult) -> None:
    data = asdict(result)
    data["schema"] = METAMORPHIC_SCHEMA
    data["schema_version"] = METAMORPHIC_SCHEMA_VERSION
    data["limitations"] = [
        "Metamorphic replay mutates captured trace evidence; it does not rerun agents, tests, Docker, models, or benchmarks.",
        "Changing transforms measure expected policy deltas, not benchmark correctness.",
        "Transformed traces are generated artifacts and should not be committed.",
    ]
    atomic_write_json(
        result.report_paths.json,
        data,
        default=lambda value: str(value) if isinstance(value, Path) else value,
        sort_keys=True,
    )
    lines = [
        "# AgentGuard Metamorphic Trace Study",
        "",
        f"- Study ID: {markdown_text(result.study_id)}",
        f"- Traces tested: {result.metrics.traces_tested}",
        f"- Transformations applied: {result.metrics.transformations_applied}",
        f"- Preserving passed/failed: {result.metrics.preserving_passed}/{result.metrics.preserving_failed}",
        f"- Changing detected/failed: {result.metrics.changing_detected}/{result.metrics.changing_failed}",
        f"- Invalid rejected/failed: {result.metrics.invalid_rejected}/{result.metrics.invalid_failed}",
        f"- Outcome stability rate: {result.metrics.outcome_stability_rate}",
        f"- Expected-delta detection rate: {result.metrics.expected_delta_detection_rate}",
        "- External execution: none",
        "",
        "## Transforms",
        "",
    ]
    lines.extend(
        f"- {markdown_text(definition.name)} "
        f"({markdown_text(definition.transform_class)}): "
        f"{markdown_text(definition.description)}"
        for definition in result.transforms
    )
    lines.extend(["", "## Cases", ""])
    lines.append("| Trace | Transform | Trial | Expected | Observed | Passed |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for case in result.cases:
        lines.append(
            f"| {markdown_table_cell(case.source_trace_id or case.source_trace)} | "
            f"{markdown_table_cell(case.transform_name)} | "
            f"{case.trial} | {markdown_table_cell(case.expected_effect)} | "
            f"{markdown_table_cell(case.observed_effect)} | "
            f"{case.robustness_passed} |"
        )
    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "Metamorphic testing verifies replay and policy-check robustness under "
            "deterministic trace transformations. It does not rerun external "
            "systems or prove that the original evidence was honestly produced.",
            "",
        ]
    )
    atomic_write_text(result.report_paths.markdown, "\n".join(lines))


def metamorphic_summary(result: MetamorphicStudyResult) -> str:
    return "\n".join(
        [
            "AgentGuard Metamorphic Trace Study",
            f"Traces tested: {result.metrics.traces_tested}",
            f"Transformations applied: {result.metrics.transformations_applied}",
            f"Preserving passed/failed: {result.metrics.preserving_passed}/{result.metrics.preserving_failed}",
            f"Changing detected/failed: {result.metrics.changing_detected}/{result.metrics.changing_failed}",
            f"Invalid rejected/failed: {result.metrics.invalid_rejected}/{result.metrics.invalid_failed}",
            f"JSON report: {result.report_paths.json}",
            f"Markdown report: {result.report_paths.markdown}",
            "External execution: none",
        ]
    )
