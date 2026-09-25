from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.evaluation import study_metrics
from agentguard.evaluation.study_metrics import (
    CONTAINED_STUDY_METRICS_SCHEMA,
    CONTAINED_STUDY_METRICS_SCHEMA_VERSION,
    ContainedStudyMetricsError,
    ContainedStudyMetricsOptions,
    generate_contained_study_metrics,
    render_contained_study_metrics_markdown,
)
from agentguard.evaluation.study_plan import (
    ContainedStudyPlanOptions,
    build_contained_study_plan,
    serialize_contained_study_plan,
)
from agentguard.evaluation.study_runner import (
    CONTAINED_STUDY_RUN_STATE_SCHEMA,
    CONTAINED_STUDY_RUN_STATE_SCHEMA_VERSION,
    CONTAINED_STUDY_TRIAL_RESULT_SCHEMA,
    CONTAINED_STUDY_TRIAL_RESULT_SCHEMA_VERSION,
)


IMAGE = "ghcr.io/example/offline-agent@sha256:" + "d" * 64
runner = CliRunner()


def _redigest(data: dict[str, object]) -> None:
    cloned = copy.deepcopy(data)
    cloned["plan_digest"] = None
    data["plan_digest"] = hashlib.sha256(
        json.dumps(cloned, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


def _write_profile(tmp_path: Path) -> Path:
    path = tmp_path / "profile.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema": "agentguard.contained-agent-profile",
                "schema_version": 1,
                "id": "offline-profile",
                "display_label": "Offline Profile",
                "image": IMAGE,
                "argv": ["/usr/local/bin/agent", "--task-file", "/workspace/TASK.md"],
                "capabilities": ["read-only"],
                "limits": {
                    "timeout_seconds": 30,
                    "cpu_limit": 1.0,
                    "memory_limit": "128m",
                    "pids_limit": 64,
                    "max_output_bytes": 4096,
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return path


def _study(tmp_path: Path, *, trials: int = 3) -> tuple[Path, Path, Path, dict[str, object]]:
    profile = _write_profile(tmp_path)
    plan = build_contained_study_plan(
        ContainedStudyPlanOptions(
            profile_paths=[profile],
            fixture_ids=["read-only-control"],
            trials=trials,
        )
    )
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(serialize_contained_study_plan(plan), encoding="utf-8")
    run_dir = tmp_path / "run"
    trials_state = {}
    for trial in plan.data["trials"]:
        trials_state[trial["trial_id"]] = {
            "artifact_alias": trial["artifact_alias"],
            "fixture_id": trial["fixture_id"],
            "outcome": None,
            "profile_id": trial["profile_id"],
            "status": "planned",
            "task_id": trial["task_id"],
            "trial_index": trial["trial_index"],
        }
    state = {
        "schema": CONTAINED_STUDY_RUN_STATE_SCHEMA,
        "schema_version": CONTAINED_STUDY_RUN_STATE_SCHEMA_VERSION,
        "protocol_version": plan.data["protocol_version"],
        "plan_digest": plan.digest,
        "plan_alias": plan_path.name,
        "profile_hashes": {profile.name: "a" * 64},
        "fixture_set_sha256": "b" * 64,
        "execution_boundary": "contained-run",
        "network": "none",
        "values_recorded": False,
        "trials": trials_state,
        "summary": {
            "completed": 0,
            "failed": 0,
            "incomplete": 0,
            "not_executed": 0,
            "stop_reason": None,
            "total_planned": trials,
        },
    }
    state_path = run_dir / "study-run-state.json"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    return plan_path, state_path, run_dir, plan.data


def _write_result(
    run_dir: Path,
    plan: dict[str, object],
    trial: dict[str, object],
    *,
    status: str,
    contained_result: str = "PASS",
    cleanup: bool = True,
    mutation: str = "complete",
    trace: str = "contained-run-report",
    replayability: str = "contained-run-report",
    check_failures: list[str] | None = None,
    policy_incidents: int | None = None,
    elapsed: float | None = None,
    cost: float | None = None,
    usage: dict[str, int] | None = None,
) -> None:
    state_path = run_dir / "study-run-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    trial_id = trial["trial_id"]
    result_path = f"trials/{trial_id}/study-evidence/contained-study-trial-result.json"
    state["trials"][trial_id].update(
        {
            "status": status,
            "outcome": "completed" if status == "completed" else "agent_or_check_failure",
            "result_path": result_path,
            "contained_run_report": f"trials/{trial_id}/study-evidence/contained-runs/report.json",
        }
    )
    state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    profile = plan["profiles"][0]
    fixture = plan["fixtures"][0]
    result = {
        "schema": CONTAINED_STUDY_TRIAL_RESULT_SCHEMA,
        "schema_version": CONTAINED_STUDY_TRIAL_RESULT_SCHEMA_VERSION,
        "plan_digest": plan["plan_digest"],
        "profile": {
            "id": profile["id"],
            "hash": profile["profile_manifest_sha256"],
            "image": profile["image"],
        },
        "fixture": {
            "id": fixture["id"],
            "hash": fixture["fixture_hash"],
            "prompt_sha256": fixture["prompt_sha256"],
            "task_id": fixture["task_id"],
        },
        "trial": {
            "artifact_alias": trial["artifact_alias"],
            "id": trial_id,
            "index": trial["trial_index"],
        },
        "contained_run": {
            "exit_code": 0 if contained_result == "PASS" else 1,
            "report_alias": "contained-runs/report.json",
            "result": contained_result,
            "cleanup_complete": cleanup,
            "preflight_status": "supported",
        },
        "evidence": {
            "check_failures": check_failures or [],
            "mutation_status": mutation,
            "prompt_alias": "task-prompt.txt",
            "trace_status": trace,
            "replayability_status": replayability,
            "workspace_alias": "prepared-workspace",
        },
    }
    if policy_incidents is not None:
        result["policy_incidents"] = policy_incidents
    if elapsed is not None:
        result["elapsed_seconds"] = elapsed
    if cost is not None:
        result["cost_usd"] = cost
    if usage is not None:
        result["usage"] = usage
    path = run_dir / result_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")


def _generate(plan_path: Path, state_path: Path, **kwargs):
    return generate_contained_study_metrics(
        ContainedStudyMetricsOptions(plan_path=plan_path, state_path=state_path, **kwargs)
    )


def test_complete_deterministic_control_study_preserves_denominators(tmp_path: Path) -> None:
    plan_path, state_path, run_dir, plan = _study(tmp_path, trials=3)
    trials = plan["trials"]
    _write_result(run_dir, plan, trials[0], status="completed", elapsed=1.2, usage={"input_tokens": 10})
    _write_result(run_dir, plan, trials[1], status="completed", policy_incidents=1, elapsed=1.5)
    _write_result(run_dir, plan, trials[2], status="failed", contained_result="FAIL", check_failures=["Functional"])

    result = _generate(plan_path, state_path)

    report = result.report
    assert report["schema"] == CONTAINED_STUDY_METRICS_SCHEMA
    assert report["schema_version"] == CONTAINED_STUDY_METRICS_SCHEMA_VERSION
    study = report["metrics"]["study"]
    assert study["planned_trials"] == 3
    assert study["executed_trials"] == {"count": 3, "denominator": 3}
    assert study["functional_success"] == {"count": 2, "denominator": 3}
    assert study["policy_compliant_success"] == {"count": 1, "denominator": 3}
    assert study["unsafe_functional_success"] == {"count": 1, "denominator": 3}
    assert study["failed_checks"] == {"count": 1, "denominator": 3}
    assert report["completion"]["complete"] is True
    assert report["optional_usage"]["input_tokens"] == {
        "available": 1,
        "denominator": 3,
        "total": 10,
    }
    unit = report["nondeterminism"]["units"][0]
    assert unit["disagreement"] is True
    assert unit["outcome_distribution"]["policy_compliant_success"] == 1
    assert unit["outcome_distribution"]["unsafe_functional_success"] == 1
    assert unit["outcome_distribution"]["failed:agent_or_check_failure"] == 1


def test_optional_output_tokens_and_guard_incident_lists_are_preserved(tmp_path: Path) -> None:
    plan_path, state_path, run_dir, plan = _study(tmp_path, trials=1)
    trial = plan["trials"][0]
    _write_result(
        run_dir,
        plan,
        trial,
        status="completed",
        usage={"input_tokens": 10, "output_tokens": 4},
    )
    state = json.loads(state_path.read_text(encoding="utf-8"))
    result_path = run_dir / state["trials"][trial["trial_id"]]["result_path"]
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["guard_incidents"] = [{"id": "guard-incident"}]
    result_path.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")

    report = _generate(plan_path, state_path).report

    study = report["metrics"]["study"]
    assert study["guard_policy_incidents"] == {"count": 1, "denominator": 1}
    assert study["unsafe_functional_success"] == {"count": 1, "denominator": 1}
    assert report["optional_usage"]["output_tokens"] == {
        "available": 1,
        "denominator": 1,
        "total": 4,
    }


def test_partial_stopped_and_missing_trials_stay_in_denominators(tmp_path: Path) -> None:
    plan_path, state_path, run_dir, plan = _study(tmp_path, trials=3)
    trials = plan["trials"]
    _write_result(run_dir, plan, trials[0], status="completed")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["trials"][trials[1]["trial_id"]]["status"] = "incomplete"
    state["trials"][trials[1]["trial_id"]]["outcome"] = "cleanup_or_liveness_failure"
    state["trials"][trials[2]["trial_id"]]["status"] = "not_executed"
    state["trials"][trials[2]["trial_id"]]["outcome"] = "not_executed_stop_condition"
    state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")

    report = _generate(plan_path, state_path).report

    study = report["metrics"]["study"]
    assert study["incomplete_trials"] == {"count": 1, "denominator": 3}
    assert study["not_executed_trials"] == {"count": 1, "denominator": 3}
    assert study["evidence_incomplete"] == {"count": 2, "denominator": 3}
    assert report["completion"]["status"] == "incomplete"
    assert report["nondeterminism"]["units"][0]["missing_or_incomplete"] == 2


def test_missing_completed_artifact_is_not_success(tmp_path: Path) -> None:
    plan_path, state_path, _run_dir, plan = _study(tmp_path, trials=1)
    trial = plan["trials"][0]
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["trials"][trial["trial_id"]].update(
        {
            "status": "completed",
            "outcome": "completed",
            "result_path": "trials/missing/study-evidence/result.json",
        }
    )
    state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")

    report = _generate(plan_path, state_path).report

    study = report["metrics"]["study"]
    assert study["functional_success"] == {"count": 0, "denominator": 1}
    assert study["evidence_incomplete"] == {"count": 1, "denominator": 1}
    assert report["completion"]["complete"] is False


def test_cleanup_diff_trace_and_replay_uncertainty_cannot_be_policy_success(tmp_path: Path) -> None:
    plan_path, state_path, run_dir, plan = _study(tmp_path, trials=1)
    _write_result(
        run_dir,
        plan,
        plan["trials"][0],
        status="completed",
        cleanup=False,
        mutation="incomplete",
        trace="unknown",
        replayability="unknown",
    )

    report = _generate(plan_path, state_path).report

    study = report["metrics"]["study"]
    assert study["cleanup_liveness_failure"] == {"count": 1, "denominator": 1}
    assert study["mutation_evidence_incomplete"] == {"count": 1, "denominator": 1}
    assert study["policy_compliant_success"] == {"count": 0, "denominator": 1}
    assert report["completion"]["status"] == "incomplete"


def test_conflicting_plan_state_and_result_identities_fail(tmp_path: Path) -> None:
    plan_path, state_path, run_dir, plan = _study(tmp_path, trials=1)
    _write_result(run_dir, plan, plan["trials"][0], status="completed")

    bad_plan = copy.deepcopy(plan)
    bad_plan["plan_digest"] = "0" * 64
    bad_plan_path = tmp_path / "bad-plan.json"
    bad_plan_path.write_text(json.dumps(bad_plan), encoding="utf-8")
    with pytest.raises(ContainedStudyMetricsError, match="plan digest"):
        _generate(bad_plan_path, state_path)

    result_path = run_dir / json.loads(state_path.read_text(encoding="utf-8"))["trials"][plan["trials"][0]["trial_id"]]["result_path"]
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["fixture"]["prompt_sha256"] = "0" * 64
    result_path.write_text(json.dumps(result), encoding="utf-8")
    with pytest.raises(ContainedStudyMetricsError, match="fixture identity"):
        _generate(plan_path, state_path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema", "wrong", "schema mismatch"),
        ("schema_version", 999, "schema version"),
        ("plan_digest", "0" * 64, "plan digest"),
    ],
)
def test_result_schema_and_plan_identity_mismatches_fail(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    plan_path, state_path, run_dir, plan = _study(tmp_path, trials=1)
    trial = plan["trials"][0]
    _write_result(run_dir, plan, trial, status="completed")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    result_path = run_dir / state["trials"][trial["trial_id"]]["result_path"]
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result[field] = value
    result_path.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")

    with pytest.raises(ContainedStudyMetricsError, match=message):
        _generate(plan_path, state_path)


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda result: result["profile"].update({"hash": "0" * 64}), "profile identity"),
        (lambda result: result["trial"].update({"id": "trial-" + "0" * 24}), "trial identity"),
    ],
)
def test_result_profile_and_trial_identity_mismatches_fail(
    tmp_path: Path,
    mutator,
    message: str,
) -> None:
    plan_path, state_path, run_dir, plan = _study(tmp_path, trials=1)
    trial = plan["trials"][0]
    _write_result(run_dir, plan, trial, status="completed")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    result_path = run_dir / state["trials"][trial["trial_id"]]["result_path"]
    result = json.loads(result_path.read_text(encoding="utf-8"))
    mutator(result)
    result_path.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")

    with pytest.raises(ContainedStudyMetricsError, match=message):
        _generate(plan_path, state_path)


@pytest.mark.parametrize(
    ("mutator", "message", "redigest"),
    [
        (lambda plan: plan.update({"schema": "wrong"}), "schema mismatch", False),
        (lambda plan: plan.update({"schema_version": 999}), "schema version", False),
        (lambda plan: plan.update({"protocol_version": "wrong"}), "protocol version", False),
        (lambda plan: plan.update({"total_planned_trial_count": 2}), "trial count", True),
        (
            lambda plan: plan["trials"].append(copy.deepcopy(plan["trials"][0])),
            "unique stable ids",
            True,
        ),
        (
            lambda plan: plan["trials"][0].update({"profile_id": "missing-profile"}),
            "unknown profile",
            True,
        ),
        (
            lambda plan: plan["trials"][0].update({"fixture_id": "missing-fixture"}),
            "unknown fixture",
            True,
        ),
    ],
)
def test_plan_validation_failures_are_controlled(
    tmp_path: Path,
    mutator,
    message: str,
    redigest: bool,
) -> None:
    plan_path, state_path, _run_dir, plan = _study(tmp_path, trials=1)
    bad_plan = copy.deepcopy(plan)
    mutator(bad_plan)
    if redigest:
        _redigest(bad_plan)
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["plan_digest"] = bad_plan["plan_digest"]
        state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    bad_plan_path = tmp_path / f"bad-plan-{message.replace(' ', '-')}.json"
    bad_plan_path.write_text(json.dumps(bad_plan, sort_keys=True), encoding="utf-8")

    with pytest.raises(ContainedStudyMetricsError, match=message):
        _generate(bad_plan_path, state_path)


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda state, _trial_id: state.update({"schema": "wrong"}), "schema mismatch"),
        (lambda state, _trial_id: state.update({"schema_version": 999}), "schema version"),
        (lambda state, _trial_id: state.update({"plan_digest": "0" * 64}), "plan digest"),
        (lambda state, _trial_id: state.update({"execution_boundary": "host"}), "boundary"),
        (lambda state, _trial_id: state.update({"network": "bridge"}), "network"),
        (lambda state, _trial_id: state.update({"values_recorded": True}), "must not record values"),
        (lambda state, trial_id: state["trials"].pop(trial_id), "trial set"),
        (
            lambda state, trial_id: state["trials"].__setitem__(
                "not-a-trial-id",
                state["trials"].pop(trial_id),
            ),
            "invalid trial id",
        ),
        (
            lambda state, trial_id: state["trials"][trial_id].update({"status": "weird"}),
            "invalid trial status",
        ),
    ],
)
def test_state_validation_failures_are_controlled(
    tmp_path: Path,
    mutator,
    message: str,
) -> None:
    plan_path, state_path, _run_dir, plan = _study(tmp_path, trials=1)
    state = json.loads(state_path.read_text(encoding="utf-8"))
    mutator(state, plan["trials"][0]["trial_id"])
    state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")

    with pytest.raises(ContainedStudyMetricsError, match=message):
        _generate(plan_path, state_path)


def test_invalid_numeric_and_path_values_fail_closed(tmp_path: Path) -> None:
    plan_path, state_path, run_dir, plan = _study(tmp_path, trials=1)
    _write_result(run_dir, plan, plan["trials"][0], status="completed", elapsed=-1)
    with pytest.raises(ContainedStudyMetricsError, match="numeric"):
        _generate(plan_path, state_path)

    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["trials"][plan["trials"][0]["trial_id"]]["result_path"] = "../escape.json"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(ContainedStudyMetricsError, match="portable artifact alias"):
        _generate(plan_path, state_path)


def test_malformed_result_artifacts_and_symlink_escape_fail_closed(tmp_path: Path) -> None:
    plan_path, state_path, run_dir, plan = _study(tmp_path, trials=1)
    trial = plan["trials"][0]
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["trials"][trial["trial_id"]].update(
        {
            "status": "completed",
            "outcome": "completed",
            "result_path": "trials/malformed/result.json",
        }
    )
    state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    malformed = run_dir / "trials/malformed/result.json"
    malformed.parent.mkdir(parents=True, exist_ok=True)
    malformed.write_text("{", encoding="utf-8")
    with pytest.raises(ContainedStudyMetricsError, match="not valid JSON"):
        _generate(plan_path, state_path)

    malformed.write_text("[]", encoding="utf-8")
    with pytest.raises(ContainedStudyMetricsError, match="JSON object"):
        _generate(plan_path, state_path)

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "result.json").write_text("{}", encoding="utf-8")
    link = run_dir / "link"
    link.symlink_to(outside, target_is_directory=True)
    state["trials"][trial["trial_id"]]["result_path"] = "link/result.json"
    state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    with pytest.raises(ContainedStudyMetricsError, match="escapes"):
        _generate(plan_path, state_path)


def test_invalid_optional_values_and_incidents_fail_closed(tmp_path: Path) -> None:
    plan_path, state_path, run_dir, plan = _study(tmp_path, trials=1)
    trial = plan["trials"][0]
    _write_result(run_dir, plan, trial, status="completed", usage={"input_tokens": 1})
    state = json.loads(state_path.read_text(encoding="utf-8"))
    result_path = run_dir / state["trials"][trial["trial_id"]]["result_path"]
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["usage"] = {"input_tokens": -1}
    result_path.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
    with pytest.raises(ContainedStudyMetricsError, match="token value"):
        _generate(plan_path, state_path)

    result["usage"] = {"input_tokens": 1}
    result["guard_incidents"] = "inline incident text"
    result_path.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
    with pytest.raises(ContainedStudyMetricsError, match="incident value"):
        _generate(plan_path, state_path)


def test_outputs_are_deterministic_schema_validated_sanitized_and_portable(tmp_path: Path) -> None:
    plan_path, state_path, run_dir, plan = _study(tmp_path, trials=1)
    _write_result(run_dir, plan, plan["trials"][0], status="completed")
    json_path = tmp_path / "metrics.json"
    md_path = tmp_path / "metrics.md"

    first = _generate(plan_path, state_path, output_json=json_path, output_markdown=md_path)
    second = _generate(plan_path, state_path)
    schema = json.loads(
        (Path(__file__).resolve().parents[2] / "agentguard/schemas/contained-study-metrics-report-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )

    assert json_path.read_text(encoding="utf-8") == json.dumps(first.report, indent=2, sort_keys=True) + "\n"
    assert first.report == second.report
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(first.report)
    rendered = json.dumps(first.report, sort_keys=True)
    assert str(tmp_path) not in rendered
    assert "/Users/" not in rendered
    markdown = md_path.read_text(encoding="utf-8")
    assert "descriptive only" in markdown
    assert all(word not in markdown.lower() for word in ["best", "safest", "superior"])


def test_reporter_does_not_execute_docker_network_subprocess_or_credentials(tmp_path: Path, monkeypatch) -> None:
    plan_path, state_path, run_dir, plan = _study(tmp_path, trials=1)
    _write_result(run_dir, plan, plan["trials"][0], status="completed")

    def blocked(*_args, **_kwargs):
        raise AssertionError("execution path should not be used")

    monkeypatch.setattr("subprocess.Popen", blocked)
    monkeypatch.setattr("socket.socket", blocked)
    monkeypatch.setattr("os.environ.get", blocked)

    report = _generate(plan_path, state_path).report

    assert report["metrics"]["study"]["completed_trials"] == {"count": 1, "denominator": 1}


def test_cli_help_and_controlled_error(tmp_path: Path) -> None:
    help_result = runner.invoke(app, ["evaluation", "study-report", "--help"])
    assert help_result.exit_code == 0
    assert "Aggregate experimental contained-study metrics without execution" in help_result.output

    result = runner.invoke(
        app,
        [
            "evaluation",
            "study-report",
            "--plan",
            str(tmp_path / "missing-plan.json"),
            "--state",
            str(tmp_path / "missing-state.json"),
        ],
    )
    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_output_inside_run_directory_is_rejected(tmp_path: Path) -> None:
    plan_path, state_path, run_dir, plan = _study(tmp_path, trials=1)
    _write_result(run_dir, plan, plan["trials"][0], status="completed")

    with pytest.raises(ContainedStudyMetricsError, match="outside the run evidence"):
        _generate(plan_path, state_path, output_json=run_dir / "metrics.json")


def test_internal_bounds_and_sanitizers_fail_closed(monkeypatch) -> None:
    with pytest.raises(ContainedStudyMetricsError, match="unsanitized"):
        study_metrics._assert_sanitized({"path": "/Users/example/secret"})
    with pytest.raises(ContainedStudyMetricsError, match="ranking"):
        study_metrics._assert_sanitized({"claim": "best"})
    with pytest.raises(ContainedStudyMetricsError, match="object"):
        study_metrics._mapping([], "field")
    with pytest.raises(ContainedStudyMetricsError, match="0 to 1"):
        study_metrics._list([1, 2], "field", 0, 1)
    with pytest.raises(ContainedStudyMetricsError, match="bounded string"):
        study_metrics._string("", "field")
    with pytest.raises(ContainedStudyMetricsError, match="control characters"):
        study_metrics._string("bad\n", "field")
    assert study_metrics._optional_string(None, "field") is None
    assert study_metrics._string_list(None, "field") == []
    with pytest.raises(ContainedStudyMetricsError, match="portable id"):
        study_metrics._portable_id("bad/slash", "field")
    with pytest.raises(ContainedStudyMetricsError, match="sha256"):
        study_metrics._sha256("not-a-digest", "field")
    with pytest.raises(ContainedStudyMetricsError, match="positive integer"):
        study_metrics._positive_int(0, "field")
    with pytest.raises(ContainedStudyMetricsError, match="artifact alias"):
        study_metrics._validate_alias("bad//alias", "field")

    monkeypatch.setattr(study_metrics, "MAX_STUDY_METRICS_GROUPS", 0)
    with pytest.raises(ContainedStudyMetricsError, match="group bound"):
        study_metrics._group([{"profile_id": "offline-profile"}], ["profile_id"])

    monkeypatch.setattr(study_metrics, "MAX_STUDY_METRICS_TRIALS", 0)
    with pytest.raises(ContainedStudyMetricsError, match="trial bound"):
        study_metrics._state_trials(
            {
                "trials": {
                    "trial-1234567890abcdef12345678": {
                        "status": "planned",
                    }
                }
            }
        )


def test_markdown_renderer_is_deterministic() -> None:
    report = {
        "protocol_version": "v0.5-preregistered-contained-study",
        "plan_digest": "a" * 64,
        "report_digest": "b" * 64,
        "completion": {
            "complete": False,
            "status": "incomplete",
            "reason": "missing",
            "planned_denominators_preserved": True,
        },
        "metrics": {
            "study": {
                "planned_trials": 0,
                **{key: {"count": 0, "denominator": 0} for key in [
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
                ]},
            }
        },
        "nondeterminism": {"units": []},
    }

    assert render_contained_study_metrics_markdown(report) == render_contained_study_metrics_markdown(report)
