from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.config.loader import load_config
from agentguard.core.orchestrator import run_benchmark
from agentguard.core.result import CheckResult
from agentguard.policy.evaluation import (
    PolicyEvaluationContext,
    evaluate_policy_checks,
)
from agentguard.traces import replay as replay_module
from agentguard.instrumentation.command_tracker import CommandEvent
from agentguard.scoring.scorer import score_checks
from agentguard.traces.execution import (
    ExecutionTrace,
    policy_snapshot_hash,
    rehash_execution_trace,
    serialize_execution_trace,
    verify_execution_trace,
    write_execution_trace,
)
from agentguard.traces.replay import (
    inspect_replayability,
    replay_trace,
    replayability_status,
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


def _write_trace(tmp_path: Path, trace: ExecutionTrace, name: str) -> Path:
    path = tmp_path / name
    write_execution_trace(trace, path)
    return path


def _v1_trace(trace: ExecutionTrace) -> ExecutionTrace:
    header = replace(
        trace.header,
        schema_version=1,
        policy_snapshot=None,
        policy_snapshot_hash=None,
    )
    return rehash_execution_trace(replace(trace, header=header))


def _replace_check_payload(
    trace: ExecutionTrace,
    *,
    name: str,
    **changes,
) -> ExecutionTrace:
    events = []
    for event in trace.events:
        if (
            event.event_type == "check_result"
            and event.payload["name"] == name
        ):
            events.append(
                replace(event, payload={**event.payload, **changes})
            )
        else:
            events.append(event)
    return rehash_execution_trace(replace(trace, events=events))


def _replace_completion_payload(
    trace: ExecutionTrace,
    **changes,
) -> ExecutionTrace:
    events = [
        replace(event, payload={**event.payload, **changes})
        if event.event_type == "execution_completed"
        else event
        for event in trace.events
    ]
    return rehash_execution_trace(replace(trace, events=events))


def test_schema_v2_policy_snapshot_is_integrity_committed(pass_result) -> None:
    trace = pass_result.report_paths.trace
    assert trace is not None
    loaded = verify_execution_trace(trace)

    assert loaded.exit_code == 0
    parsed = inspect_replayability(trace)[0]
    assert parsed.replayable is True


def test_sensitive_policy_pattern_is_redacted_and_non_replayable(
    pass_result,
) -> None:
    from agentguard.provenance.manifest import sha256_file
    from agentguard.traces.execution import (
        build_execution_trace,
        build_policy_snapshot,
    )

    canary = "REPLAY-POLICY-CANARY-28B"
    config = replace(
        load_config(pass_result.config_path),
        agent_environment={"TOKEN": canary},
        secret_patterns=[canary],
    )
    snapshot = build_policy_snapshot(config)

    assert canary not in str(snapshot)
    assert snapshot.secret_patterns == ["[REDACTED]"]
    assert "secret_patterns" in snapshot.redacted_inputs
    serialized = serialize_execution_trace(
        build_execution_trace(
            pass_result,
            created_at="2026-06-14T12:00:00+00:00",
            configuration_hash=sha256_file(pass_result.config_path),
            agentguard_version="test",
            agentguard_commit=None,
            agent_version=None,
            policy_summary="test",
            sandbox_summary="local",
            source_report_id=None,
            source_manifest_id=None,
            policy_snapshot=snapshot,
            sensitive_values=[canary],
        )
    )
    assert canary not in serialized
    from agentguard.traces.execution import load_execution_trace

    trace = load_execution_trace(_trace_path(pass_result))
    status = replayability_status(
        replace(trace, header=replace(trace.header, policy_snapshot=snapshot))
    )
    assert status.replayable is False
    assert "redacted" in status.reasons[0]


def test_existing_v1_trace_verifies_but_is_non_replayable(
    pass_result,
    tmp_path: Path,
) -> None:
    from agentguard.traces.execution import load_execution_trace

    path = _write_trace(
        tmp_path,
        _v1_trace(load_execution_trace(_trace_path(pass_result))),
        "v1.jsonl",
    )

    assert verify_execution_trace(path).exit_code == 0
    status, _ = inspect_replayability(path)
    assert status.replayable is False
    assert "policy_snapshot" in status.missing_inputs
    assert runner.invoke(
        app, ["trace", "replayability", str(path)]
    ).exit_code == 1
    assert runner.invoke(app, ["trace", "replay", str(path)]).exit_code == 2


@pytest.mark.parametrize("fixture_name", ["pass_result", "fail_result"])
def test_pass_and_fail_replay_exactly(
    request,
    fixture_name: str,
    tmp_path: Path,
) -> None:
    result = request.getfixturevalue(fixture_name)
    replay = replay_trace(
        _trace_path(result),
        output_dir=tmp_path / fixture_name,
    )

    assert replay.equivalence == "exact"
    assert replay.recorded_score == replay.recomputed_score
    assert replay.recorded_result == replay.recomputed_result
    assert replay.no_external_execution is True
    assert replay.report_paths.json.is_file()
    assert replay.report_paths.markdown.is_file()
    assert "External execution: none" in replay.report_paths.markdown.read_text(
        encoding="utf-8"
    )


def test_replay_invokes_no_external_execution(
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

    replay = replay_trace(
        _trace_path(pass_result),
        output_dir=tmp_path,
    )

    assert replay.equivalence == "exact"


def test_live_and_replay_call_shared_check_implementations(
    pass_result,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []
    original = evaluate_policy_checks

    def recording(context, *, enabled_identifiers=None):
        calls.append(enabled_identifiers)
        return original(
            context,
            enabled_identifiers=enabled_identifiers,
        )

    monkeypatch.setattr(
        "agentguard.traces.replay.evaluate_policy_checks",
        recording,
    )
    replay_trace(_trace_path(pass_result), output_dir=tmp_path)

    assert len(calls) == 1
    assert calls[0] == [
        "tests-passed",
        "forbidden-paths",
        "test-tampering",
        "unsafe-commands",
        "scope-adherence",
        "diff-size",
        "secret-scan",
    ]


def test_recorded_check_is_comparison_target_not_recomputed_input(
    pass_result,
    tmp_path: Path,
) -> None:
    from agentguard.traces.execution import load_execution_trace

    trace = load_execution_trace(_trace_path(pass_result))
    changed = _replace_check_payload(
        trace,
        name="Tests passed",
        passed=False,
        message="altered recorded outcome",
        evidence=["altered"],
        score_contribution=-30,
    )
    path = _write_trace(tmp_path, changed, "recorded-check-changed.jsonl")

    replay = replay_trace(path, output_dir=tmp_path / "replay")

    recomputed = next(
        check for check in replay.recomputed_checks if check.name == "Tests passed"
    )
    assert recomputed.passed is True
    assert replay.equivalence == "divergent"
    assert verify_execution_trace(path).exit_code == 0


def test_evidence_and_final_result_divergence_are_detected(
    pass_result,
    tmp_path: Path,
) -> None:
    from agentguard.traces.execution import load_execution_trace

    trace = load_execution_trace(_trace_path(pass_result))
    changed = _replace_check_payload(
        trace,
        name="Tests passed",
        evidence=["different recorded evidence"],
    )
    changed = _replace_completion_payload(
        changed,
        result="FAIL",
        score=1,
        failed_checks=["Tests passed"],
    )
    path = _write_trace(tmp_path, changed, "evidence-result-changed.jsonl")

    replay = replay_trace(path, output_dir=tmp_path / "direct")
    default_cli = runner.invoke(
        app,
        [
            "trace",
            "replay",
            str(path),
            "--output-dir",
            str(tmp_path / "cli-default"),
        ],
    )
    allowed_cli = runner.invoke(
        app,
        [
            "trace",
            "replay",
            str(path),
            "--output-dir",
            str(tmp_path / "cli-allowed"),
            "--allow-divergence",
        ],
    )

    assert replay.equivalence == "divergent"
    assert {"score", "result", "failed_checks"} <= {
        item.field for item in replay.divergences
    }
    assert default_cli.exit_code == 1
    assert allowed_cli.exit_code == 0


def test_policy_snapshot_hash_tampering_is_rejected(
    pass_result,
    tmp_path: Path,
) -> None:
    path = tmp_path / "snapshot-tampered.jsonl"
    path.write_bytes(_trace_path(pass_result).read_bytes())
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace('"max_files_changed":3', '"max_files_changed":4', 1),
        encoding="utf-8",
    )

    assert verify_execution_trace(path).exit_code == 2
    assert runner.invoke(app, ["trace", "replay", str(path)]).exit_code == 2


def test_valid_policy_weight_change_detects_score_divergence(
    fail_result,
    tmp_path: Path,
) -> None:
    from agentguard.traces.execution import load_execution_trace

    trace = load_execution_trace(_trace_path(fail_result))
    snapshot = trace.header.policy_snapshot
    assert snapshot is not None
    changed_snapshot = replace(
        snapshot,
        score_weights={**snapshot.score_weights, "error": 17},
    )
    header = replace(
        trace.header,
        policy_snapshot=changed_snapshot,
        policy_snapshot_hash=policy_snapshot_hash(changed_snapshot),
    )
    path = _write_trace(
        tmp_path,
        rehash_execution_trace(replace(trace, header=header)),
        "weight-changed.jsonl",
    )

    replay = replay_trace(path, output_dir=tmp_path / "replay")

    assert replay.equivalence == "divergent"
    assert replay.recorded_score != replay.recomputed_score


def test_unsupported_check_and_missing_policy_input_are_non_replayable(
    pass_result,
) -> None:
    from agentguard.traces.execution import load_execution_trace

    trace = load_execution_trace(_trace_path(pass_result))
    snapshot = trace.header.policy_snapshot
    assert snapshot is not None
    unsupported = replace(
        snapshot,
        enabled_checks=[*snapshot.enabled_checks, "future-check"],
    )
    missing = replace(
        snapshot,
        severities={
            key: value
            for key, value in snapshot.severities.items()
            if key != "tests-passed"
        },
    )

    assert replayability_status(
        replace(trace, header=replace(trace.header, policy_snapshot=unsupported))
    ).replayable is False
    missing_status = replayability_status(
        replace(trace, header=replace(trace.header, policy_snapshot=missing))
    )
    assert missing_status.replayable is False
    assert "severity:tests-passed" in missing_status.missing_inputs


def test_replayability_reports_snapshot_and_truncation_reasons(
    pass_result,
) -> None:
    from agentguard.traces.execution import load_execution_trace

    trace = load_execution_trace(_trace_path(pass_result))
    snapshot = trace.header.policy_snapshot
    assert snapshot is not None
    inconsistent = replace(
        snapshot,
        command_policy_patterns=["different"],
        score_weights={"error": 30},
    )
    no_snapshot = replayability_status(
        replace(trace, header=replace(trace.header, policy_snapshot=None))
    )
    inconsistent_status = replayability_status(
        replace(trace, header=replace(trace.header, policy_snapshot=inconsistent))
    )
    events = []
    for event in trace.events:
        if event.event_type == "test_result":
            events.append(
                replace(
                    event,
                    payload={
                        **event.payload,
                        "truncation": {"command": True},
                    },
                )
            )
        elif event.event_type == "execution_completed":
            events.append(
                replace(
                    event,
                    payload={
                        **event.payload,
                        "modified_files": {
                            **event.payload["modified_files"],
                            "truncated": True,
                        },
                    },
                )
            )
        else:
            events.append(event)
    truncated_status = replayability_status(replace(trace, events=events))

    assert no_snapshot.missing_inputs == ["policy_snapshot"]
    assert "score_weights" in inconsistent_status.missing_inputs
    assert any(
        "inconsistent" in reason for reason in inconsistent_status.reasons
    )
    assert any("test_result" in reason for reason in truncated_status.reasons)
    assert any(
        "Modified-file evidence" in reason
        for reason in truncated_status.reasons
    )


def test_reconstructs_file_categories_and_rejects_inconsistency(
    fail_result,
) -> None:
    from agentguard.traces.execution import load_execution_trace

    trace = load_execution_trace(_trace_path(fail_result))
    evidence = replay_module.reconstruct_replay_evidence(trace)

    assert evidence.diff_summary.modified_files == ["tests/test_auth.py"]
    assert evidence.diff_summary.added_files == []
    assert evidence.diff_summary.deleted_files == []
    assert evidence.diff_summary.changed_files == ["tests/test_auth.py"]

    file_event = next(
        event for event in trace.events if event.event_type == "file_change"
    )
    added_trace = replace(
        trace,
        events=[
            replace(
                event,
                payload={**event.payload, "change_type": "added"},
            )
            if event is file_event
            else event
            for event in trace.events
        ],
    )
    deleted_trace = replace(
        trace,
        events=[
            replace(
                event,
                payload={**event.payload, "change_type": "deleted"},
            )
            if event is file_event
            else event
            for event in trace.events
        ],
    )
    assert replay_module.reconstruct_replay_evidence(
        added_trace
    ).diff_summary.added_files == ["tests/test_auth.py"]
    assert replay_module.reconstruct_replay_evidence(
        deleted_trace
    ).diff_summary.deleted_files == ["tests/test_auth.py"]

    completed = next(
        event for event in trace.events if event.event_type == "execution_completed"
    )
    inconsistent = replace(
        trace,
        events=[
            replace(
                event,
                payload={
                    **event.payload,
                    "modified_files": {
                        **event.payload["modified_files"],
                        "paths": ["different.py"],
                    },
                },
            )
            if event is completed
            else event
            for event in trace.events
        ],
    )
    with pytest.raises(ValueError, match="inconsistent"):
        replay_module.reconstruct_replay_evidence(inconsistent)


def test_check_comparison_classifies_semantic_and_missing_results(
    pass_result,
) -> None:
    from agentguard.traces.execution import load_execution_trace

    trace = load_execution_trace(_trace_path(pass_result))
    snapshot = trace.header.policy_snapshot
    assert snapshot is not None
    recorded = [
        CheckResult(
            name="Tests passed",
            passed=True,
            severity="error",
            message="recorded display text",
            evidence=["pytest exited 0"],
        )
    ]
    recomputed = [
        replace(recorded[0], message="recomputed display text"),
        CheckResult(
            name="Extra",
            passed=True,
            severity="info",
            message="extra",
        ),
    ]

    comparisons, divergences = replay_module._compare_checks(
        recorded,
        [0],
        recomputed,
        snapshot,
    )

    assert comparisons[0].classification == "semantic"
    assert comparisons[1].classification == "divergent"
    assert comparisons[1].recorded is None
    assert len(divergences) == 1


def test_shared_policy_evaluation_rejects_unknown_check(pass_result) -> None:
    config = load_config(pass_result.config_path)
    context = PolicyEvaluationContext(
        config=config,
        test_result=pass_result.test_result,
        diff_summary=pass_result.diff_summary,
        command_events=pass_result.command_events,
    )

    with pytest.raises(ValueError, match="Unsupported replay check"):
        evaluate_policy_checks(context, enabled_identifiers=["future-check"])


def test_replay_rejects_malformed_docker_identity(pass_result) -> None:
    trace = replay_module.load_execution_trace(_trace_path(pass_result))
    test_index = next(
        index
        for index, event in enumerate(trace.events)
        if event.event_type == "test_result"
    )
    event = trace.events[test_index]
    payload = dict(event.payload)
    payload["docker_image"] = {
        "configured_reference": "example/app:latest",
        "local_image_id": "sha256:" + "1" * 64,
        "executed_image_id": "sha256:" + "1" * 64,
        "registry_digest": None,
        "platform": "linux/amd64",
        "pull_policy": "surprise",
        "cache_status": "present",
    }
    events = list(trace.events)
    events[test_index] = replace(event, payload=payload)
    malformed = replace(trace, events=events)

    with pytest.raises(ValueError, match="pull policy"):
        replay_module.reconstruct_replay_evidence(malformed)


def test_source_strict_and_non_strict_replay_behavior(
    pass_result,
    tmp_path: Path,
) -> None:
    detached = tmp_path / "trace.jsonl"
    detached.write_bytes(_trace_path(pass_result).read_bytes())

    replay = replay_trace(
        detached,
        output_dir=tmp_path / "non-strict",
    )
    assert replay.equivalence == "exact"
    with pytest.raises(ValueError, match="non-replayable"):
        replay_trace(
            detached,
            output_dir=tmp_path / "strict",
            strict_sources=True,
        )
    strict_cli = runner.invoke(
        app,
        [
            "trace",
            "replayability",
            str(detached),
            "--strict-sources",
        ],
    )
    assert strict_cli.exit_code == 1


def test_output_overwrite_and_cli_exit_codes(
    pass_result,
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    first = runner.invoke(
        app,
        [
            "trace",
            "replay",
            str(_trace_path(pass_result)),
            "--output-dir",
            str(output),
        ],
    )
    duplicate = runner.invoke(
        app,
        [
            "trace",
            "replay",
            str(_trace_path(pass_result)),
            "--output-dir",
            str(output),
        ],
    )
    forced = runner.invoke(
        app,
        [
            "trace",
            "replay",
            str(_trace_path(pass_result)),
            "--output-dir",
            str(output),
            "--force",
        ],
    )

    assert first.exit_code == 0
    assert duplicate.exit_code == 2
    assert forced.exit_code == 0


def test_all_current_checks_recompute_from_trace_evidence(
    pass_result,
    tmp_path: Path,
) -> None:
    config = load_config(pass_result.config_path)
    diff = replace(
        pass_result.diff_summary,
        modified_files=["tests/test_auth.py"],
        added_files=[".env", "docs/outside.md", "src/extra.py"],
        deleted_files=[],
        lines_added=500,
        lines_deleted=500,
    )
    context = PolicyEvaluationContext(
        config=config,
        test_result=replace(pass_result.test_result, exit_code=1),
        diff_summary=diff,
        command_events=pass_result.command_events,
    )
    checks = evaluate_policy_checks(context)
    score = score_checks(checks)
    synthetic = replace(
        pass_result,
        result=score.result,
        score=score.score,
        test_result=context.test_result,
        diff_summary=diff,
        check_results=checks,
    )
    from agentguard.traces.execution import (
        build_execution_trace,
        build_policy_snapshot,
    )
    from agentguard.provenance.manifest import sha256_file

    trace = build_execution_trace(
        synthetic,
        created_at="2026-06-14T12:00:00+00:00",
        configuration_hash=sha256_file(synthetic.config_path),
        agentguard_version="test",
        agentguard_commit=None,
        agent_version=None,
        policy_summary="test",
        sandbox_summary="local",
        source_report_id=None,
        source_manifest_id=None,
        policy_snapshot=build_policy_snapshot(config),
    )
    path = _write_trace(tmp_path, trace, "all-checks.jsonl")
    replay = replay_trace(path, output_dir=tmp_path / "replay")

    assert replay.equivalence == "exact"
    assert {check.name for check in replay.recomputed_checks} == {
        "Tests passed",
        "Forbidden paths",
        "Test tampering",
        "Unsafe commands",
        "Scope adherence",
        "Diff size",
        "Secret scan",
    }
    assert serialize_execution_trace(trace).endswith("\n")


def test_preflight_timeout_and_output_truncation_replay(
    pass_result,
    tmp_path: Path,
) -> None:
    config = load_config(pass_result.config_path)
    command = CommandEvent(
        command=["rm", "-rf", "important_data"],
        command_text="rm -rf important_data",
        cwd=str(pass_result.repo_dir),
        exit_code=126,
        stdout="",
        stderr="blocked",
        duration_seconds=0.0,
        executed=False,
        blocked=True,
        reason="preflight",
        timed_out=False,
        stdout_truncated=True,
        stderr_truncated=True,
        preflight_blocked=True,
        preflight_matched_patterns=["rm -rf"],
        policy_mode="enforce",
        agent_name="synthetic-agent",
    )
    test_result = replace(
        pass_result.test_result,
        exit_code=124,
        timed_out=True,
        stdout_truncated=True,
        stderr_truncated=True,
    )
    context = PolicyEvaluationContext(
        config=config,
        test_result=test_result,
        diff_summary=pass_result.diff_summary,
        command_events=[command],
    )
    checks = evaluate_policy_checks(context)
    score = score_checks(checks)
    synthetic = replace(
        pass_result,
        result=score.result,
        score=score.score,
        test_result=test_result,
        command_events=[command],
        check_results=checks,
    )
    from agentguard.provenance.manifest import sha256_file
    from agentguard.traces.execution import (
        build_execution_trace,
        build_policy_snapshot,
    )

    trace = build_execution_trace(
        synthetic,
        created_at="2026-06-14T12:00:00+00:00",
        configuration_hash=sha256_file(synthetic.config_path),
        agentguard_version="test",
        agentguard_commit=None,
        agent_version=None,
        policy_summary="test",
        sandbox_summary="local",
        source_report_id=None,
        source_manifest_id=None,
        policy_snapshot=build_policy_snapshot(config),
    )
    path = _write_trace(tmp_path, trace, "preflight-timeout.jsonl")
    replay = replay_trace(path, output_dir=tmp_path / "replay")

    assert replay.equivalence == "exact"
    unsafe = next(
        check for check in replay.recomputed_checks if check.name == "Unsafe commands"
    )
    assert unsafe.evidence == [
        "rm -rf important_data matched pattern 'rm -rf' (preflight blocked)"
    ]
