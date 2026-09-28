import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

import agentguard.cli.main as cli_main
from agentguard.cli.main import app
from agentguard.evaluation.live_egress_gateway import (
    EgressDestinationRule,
    LiveStudyEgressPolicy,
    LiveStudyEgressTrialResult,
    build_live_study_egress_manifest,
    evaluate_live_study_egress_destination,
    live_study_egress_policy_digest,
)
from agentguard.evaluation.live_study_authorization import (
    LIVE_STUDY_AUTHORIZATION_SCHEMA,
    LIVE_STUDY_AUTHORIZATION_SCHEMA_VERSION,
    LiveStudyAuthorization,
    LiveStudyAuthorizationError,
    LiveStudyLocalRehearsalResult,
    canonical_live_study_authorization,
    commit_live_study_authorization_use,
    invalidate_live_study_authorization,
    live_study_authorization_digest,
    live_study_authorization_status,
    load_live_study_authorization,
    parse_live_study_authorization,
    rehearse_live_study_authorization_locally,
    reserve_live_study_authorization_use,
    resolve_authorized_credentials,
    validate_live_study_authorization_scope,
)


PLAN_DIGEST = "1" * 64
PROFILE_HASH = "2" * 64
FIXTURE_HASH = "3" * 64
POLICY_DIGEST = "4" * 64
REDACTION_DIGEST = "5" * 64
TRIAL_ID = "trial-0123456789abcdef01234567"
AGENT_IMAGE = "example.com/agentguard/agent@sha256:" + "a" * 64
GATEWAY_IMAGE = "example.com/agentguard/gateway@sha256:" + "b" * 64
runner = CliRunner()


def _timestamp(offset_seconds: int) -> str:
    return (
        datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def _artifact() -> dict[str, object]:
    return {
        "authorization_id": "auth-issue-303",
        "credential_env_names": ["AGENTGUARD_FAKE_API_KEY"],
        "destinations": [{"host": "mock-approved.test", "port": 443}],
        "egress_policy_digest": POLICY_DIGEST,
        "evidence_bounds": {"max_output_bytes": 200000},
        "expires_at": _timestamp(3600),
        "fixtures": [{"hash": FIXTURE_HASH, "id": "fixture", "task_id": "task"}],
        "images": {"agent": AGENT_IMAGE, "gateway": GATEWAY_IMAGE},
        "issued_at": _timestamp(-60),
        "issuer": "agentguard-maintainer",
        "limits": {
            "max_turns": 4,
            "per_trial_cost_usd": 0.0,
            "per_trial_input_tokens": 1000,
            "per_trial_output_tokens": 1000,
            "per_trial_timeout_seconds": 30,
            "total_cost_usd": 0.0,
            "total_input_tokens": 1000,
            "total_output_tokens": 1000,
        },
        "max_trial_count": 1,
        "not_before": _timestamp(-30),
        "plan_digest": PLAN_DIGEST,
        "profile": {"hash": PROFILE_HASH, "id": "profile"},
        "protocol_version": "v0.5-preregistered-contained-study",
        "provider": {"model_id": "mock-model", "provider_id": "mock-provider"},
        "publication_redaction_policy_digest": REDACTION_DIGEST,
        "schema": LIVE_STUDY_AUTHORIZATION_SCHEMA,
        "schema_version": LIVE_STUDY_AUTHORIZATION_SCHEMA_VERSION,
        "stop_thresholds": {"max_failures": 1},
        "trials": [TRIAL_ID],
    }


def _rehearsal_artifact() -> dict[str, object]:
    artifact = _artifact()
    artifact["egress_policy_digest"] = live_study_egress_policy_digest(
        LiveStudyEgressPolicy(
            destinations=(
                EgressDestinationRule(
                    "mock-approved.test",
                    443,
                    purpose="local authorization rehearsal",
                    test_only=True,
                ),
            )
        )
    )
    return artifact


def test_authorization_is_canonical_digestible_and_scope_bound(tmp_path: Path) -> None:
    artifact = _artifact()
    canonical = canonical_live_study_authorization(artifact)
    path = tmp_path / "auth.json"
    path.write_text(canonical + "\n", encoding="utf-8")

    loaded = load_live_study_authorization(path)
    assert loaded.digest == live_study_authorization_digest(artifact)
    validate_live_study_authorization_scope(
        loaded,
        protocol_version="v0.5-preregistered-contained-study",
        plan_digest=PLAN_DIGEST,
        profile_id="profile",
        profile_hash=PROFILE_HASH,
        fixture_id="fixture",
        fixture_hash=FIXTURE_HASH,
        task_id="task",
        trial_id=TRIAL_ID,
        agent_image=AGENT_IMAGE,
        gateway_image=GATEWAY_IMAGE,
        egress_policy_digest=POLICY_DIGEST,
        destinations=[{"host": "mock-approved.test", "port": 443}],
        credential_env_names=["AGENTGUARD_FAKE_API_KEY"],
    )

    pretty = tmp_path / "pretty.json"
    pretty.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    with pytest.raises(LiveStudyAuthorizationError, match="canonical"):
        load_live_study_authorization(pretty)


@pytest.mark.parametrize(
    "mutation, message",
    [
        ({"schema_version": 99}, "Unsupported"),
        (
            {
                "expires_at": "2020-01-02T00:00:00Z",
                "issued_at": "2020-01-01T00:00:00Z",
                "not_before": "2020-01-01T00:00:01Z",
            },
            "expired",
        ),
        ({"destinations": [{"host": "*.example.test", "port": 443}]}, "exact"),
        ({"images": {"agent": "example.com/agent:latest", "gateway": GATEWAY_IMAGE}}, "immutable"),
        ({"issuer": "sk-secret-value"}, "credential value"),
        ({"credential_env_names": ["bad-name"]}, "credential name"),
    ],
)
def test_authorization_rejects_malformed_or_unsafe_artifacts(mutation, message) -> None:
    artifact = _artifact()
    artifact.update(mutation)
    with pytest.raises(LiveStudyAuthorizationError, match=message):
        parse_live_study_authorization(artifact)


def test_authorization_rejects_non_object_and_invalid_schema() -> None:
    with pytest.raises(LiveStudyAuthorizationError, match="must be an object"):
        parse_live_study_authorization([])

    artifact = _artifact()
    artifact["schema"] = "wrong"
    with pytest.raises(LiveStudyAuthorizationError, match="Invalid"):
        parse_live_study_authorization(artifact)


def test_authorization_unknown_field_diagnostic_is_sanitized() -> None:
    artifact = _artifact()
    artifact["sk-hostile\nfield"] = True

    with pytest.raises(LiveStudyAuthorizationError) as error:
        parse_live_study_authorization(artifact)

    message = str(error.value)
    assert "unknown field(s)" in message
    assert "sk-hostile" not in message
    assert "\n" not in message


def test_authorization_loader_rejects_unavailable_oversized_and_malformed_files(
    tmp_path: Path,
) -> None:
    with pytest.raises(LiveStudyAuthorizationError, match="unavailable"):
        load_live_study_authorization(tmp_path / "missing.json")

    oversized = tmp_path / "oversized.json"
    oversized.write_text("x" * (64 * 1024 + 1), encoding="utf-8")
    with pytest.raises(LiveStudyAuthorizationError, match="size bound"):
        load_live_study_authorization(oversized)

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{not-json", encoding="utf-8")
    with pytest.raises(LiveStudyAuthorizationError, match="malformed JSON"):
        load_live_study_authorization(malformed)


@pytest.mark.parametrize(
    "mutation, message",
    [
        ({"not_before": _timestamp(3600), "expires_at": _timestamp(7200)}, "not yet valid"),
        (
            {
                "expires_at": "2099-01-01T00:00:00Z",
                "issued_at": "2098-01-01T00:00:02Z",
                "not_before": "2098-01-01T00:00:01Z",
            },
            "timestamp order",
        ),
        ({"expires_at": _timestamp(8 * 24 * 60 * 60)}, "lifetime"),
        ({"max_trial_count": 2}, "trial count"),
        ({"fixtures": [_artifact()["fixtures"][0], _artifact()["fixtures"][0]]}, "Duplicate"),
        ({"destinations": [{"host": "mock-approved.test", "port": 443}, {"host": "mock-approved.test", "port": 443}]}, "Duplicate"),
        ({"trials": [TRIAL_ID, TRIAL_ID]}, "Duplicate"),
        ({"credential_env_names": ["AGENTGUARD_FAKE_API_KEY", "AGENTGUARD_FAKE_API_KEY"]}, "Duplicate"),
        ({"evidence_bounds": {}}, "empty"),
        ({"evidence_bounds": {"bad": object()}}, "unsupported"),
        ({"limits": {**_artifact()["limits"], "max_turns": 0}}, "out of bounds"),
        ({"limits": {**_artifact()["limits"], "total_cost_usd": -1.0}}, "out of bounds"),
        ({"authorization_id": "bad id"}, "invalid"),
        ({"plan_digest": "not-a-sha"}, "sha256"),
        ({"issuer": "bad\nissuer"}, "control characters"),
        ({"issued_at": "2098-99-99T00:00:00Z"}, "timestamp is invalid"),
        ({"issued_at": "2098-01-01T00:00:00+00:00"}, "must be UTC"),
        ({"images": {"agent": AGENT_IMAGE, "gateway": "example.com/gateway:latest"}}, "immutable"),
        ({"evidence_bounds": {"too_big": 1_000_000_001}}, "out of bounds"),
        ({"evidence_bounds": {"bad_float": 1_000_001.0}}, "out of bounds"),
        ({"limits": {**_artifact()["limits"], "total_input_tokens": -1}}, "out of bounds"),
        ({"credential_env_names": "AGENTGUARD_FAKE_API_KEY"}, "bound"),
        ({"profile": []}, "must be an object"),
        ({"issuer": ""}, "bounded"),
        ({"unknown": True}, "unknown field"),
    ],
)
def test_authorization_rejects_conflicts_bounds_and_hostile_shapes(
    mutation,
    message,
) -> None:
    artifact = _artifact()
    artifact.update(mutation)
    with pytest.raises(LiveStudyAuthorizationError, match=message):
        parse_live_study_authorization(artifact)


def test_authorization_accepts_small_primitive_bounds() -> None:
    artifact = _artifact()
    artifact["evidence_bounds"] = {"flag": True, "name": "bound", "ratio": 1.25}

    parsed = parse_live_study_authorization(artifact)

    assert parsed["evidence_bounds"] == {
        "flag": True,
        "name": "bound",
        "ratio": 1.25,
    }


def test_credentials_resolve_only_by_authorized_names() -> None:
    auth = LiveStudyAuthorization(
        data=parse_live_study_authorization(_artifact()),
        digest=live_study_authorization_digest(_artifact()),
    )

    resolved = resolve_authorized_credentials(
        auth,
        profile_required_env=["AGENTGUARD_FAKE_API_KEY"],
        environ={"AGENTGUARD_FAKE_API_KEY": "fake-canary"},
    )
    assert resolved == {"AGENTGUARD_FAKE_API_KEY": "fake-canary"}

    with pytest.raises(LiveStudyAuthorizationError, match="Missing"):
        resolve_authorized_credentials(
            auth,
            profile_required_env=["AGENTGUARD_FAKE_API_KEY"],
            environ={},
        )
    with pytest.raises(LiveStudyAuthorizationError, match="do not match"):
        resolve_authorized_credentials(
            auth,
            profile_required_env=["OTHER_KEY"],
            environ={"OTHER_KEY": "fake"},
        )
    with pytest.raises(TypeError):
        resolve_authorized_credentials(  # type: ignore[call-arg]
            auth,
            profile_required_env=["AGENTGUARD_FAKE_API_KEY"],
        )


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"protocol_version": "wrong"}, "protocol"),
        ({"plan_digest": "9" * 64}, "plan"),
        ({"profile_id": "other"}, "profile"),
        ({"profile_hash": "9" * 64}, "profile"),
        ({"fixture_id": "other"}, "fixture"),
        ({"fixture_hash": "9" * 64}, "fixture"),
        ({"task_id": "other"}, "fixture"),
        ({"trial_id": "trial-deadbeefdeadbeefdeadbeef"}, "trial"),
        ({"agent_image": "example.com/other@sha256:" + "a" * 64}, "image"),
        ({"gateway_image": "example.com/other@sha256:" + "b" * 64}, "image"),
        ({"egress_policy_digest": "9" * 64}, "egress"),
        ({"destinations": [{"host": "other.test", "port": 443}]}, "destination"),
        ({"credential_env_names": ["OTHER_KEY"]}, "credential"),
    ],
)
def test_authorization_scope_rejects_every_changed_binding(kwargs, message) -> None:
    auth = LiveStudyAuthorization(
        data=parse_live_study_authorization(_artifact()),
        digest=live_study_authorization_digest(_artifact()),
    )
    base = {
        "protocol_version": "v0.5-preregistered-contained-study",
        "plan_digest": PLAN_DIGEST,
        "profile_id": "profile",
        "profile_hash": PROFILE_HASH,
        "fixture_id": "fixture",
        "fixture_hash": FIXTURE_HASH,
        "task_id": "task",
        "trial_id": TRIAL_ID,
        "agent_image": AGENT_IMAGE,
        "gateway_image": GATEWAY_IMAGE,
        "egress_policy_digest": POLICY_DIGEST,
        "destinations": [{"host": "mock-approved.test", "port": 443}],
        "credential_env_names": ["AGENTGUARD_FAKE_API_KEY"],
    }
    base.update(kwargs)
    with pytest.raises(LiveStudyAuthorizationError, match=message):
        validate_live_study_authorization_scope(auth, **base)


def test_atomic_use_commit_duplicate_and_status(tmp_path: Path) -> None:
    auth = LiveStudyAuthorization(
        data=parse_live_study_authorization(_artifact()),
        digest=live_study_authorization_digest(_artifact()),
    )
    ledger = tmp_path / "ledger.json"

    reserve_live_study_authorization_use(
        ledger,
        auth,
        plan_digest=PLAN_DIGEST,
        trial_id=TRIAL_ID,
    )
    with pytest.raises(LiveStudyAuthorizationError, match="already used"):
        reserve_live_study_authorization_use(
            ledger,
            auth,
            plan_digest=PLAN_DIGEST,
            trial_id=TRIAL_ID,
        )
    commit_live_study_authorization_use(
        ledger,
        auth,
        plan_digest=PLAN_DIGEST,
        trial_id=TRIAL_ID,
    )
    status = live_study_authorization_status(ledger, auth)
    assert status["recorded_uses"] == 1
    assert status["real_live_execution"] == "unapproved"


def test_atomic_use_rejects_commit_without_reserve_and_invalidated_reuse(
    tmp_path: Path,
) -> None:
    auth = LiveStudyAuthorization(
        data=parse_live_study_authorization(_artifact()),
        digest=live_study_authorization_digest(_artifact()),
    )
    ledger = tmp_path / "ledger.json"

    with pytest.raises(LiveStudyAuthorizationError, match="not reserved"):
        commit_live_study_authorization_use(
            ledger,
            auth,
            plan_digest=PLAN_DIGEST,
            trial_id=TRIAL_ID,
        )

    reserve_live_study_authorization_use(
        ledger,
        auth,
        plan_digest=PLAN_DIGEST,
        trial_id=TRIAL_ID,
    )
    invalidate_live_study_authorization(
        ledger,
        auth,
        plan_digest=PLAN_DIGEST,
        trial_id=TRIAL_ID,
        reason="cleanup uncertainty",
    )
    with pytest.raises(LiveStudyAuthorizationError, match="invalidated"):
        reserve_live_study_authorization_use(
            ledger,
            auth,
            plan_digest=PLAN_DIGEST,
            trial_id="trial-deadbeefdeadbeefdeadbeef",
        )


def test_atomic_use_rejects_lock_identity_plan_and_malformed_ledgers(
    tmp_path: Path,
) -> None:
    auth = LiveStudyAuthorization(
        data=parse_live_study_authorization(_artifact()),
        digest=live_study_authorization_digest(_artifact()),
    )
    ledger = tmp_path / "ledger.json"
    lock = ledger.with_suffix(".json.lock")
    lock.write_text("other", encoding="utf-8")
    with pytest.raises(LiveStudyAuthorizationError, match="already in use"):
        reserve_live_study_authorization_use(
            ledger,
            auth,
            plan_digest=PLAN_DIGEST,
            trial_id=TRIAL_ID,
        )
    lock.unlink()

    ledger.write_text("[1]\n", encoding="utf-8")
    with pytest.raises(LiveStudyAuthorizationError, match="malformed"):
        live_study_authorization_status(ledger, auth)

    ledger.write_text("{not-json", encoding="utf-8")
    with pytest.raises(LiveStudyAuthorizationError, match="unreadable"):
        live_study_authorization_status(ledger, auth)

    ledger.write_text(
        json.dumps(
            {
                "authorization_id": "other",
                "invalidated": False,
                "uses": {},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(LiveStudyAuthorizationError, match="identity"):
        reserve_live_study_authorization_use(
            ledger,
            auth,
            plan_digest=PLAN_DIGEST,
            trial_id=TRIAL_ID,
        )

    ledger.write_text(
        json.dumps(
            {
                "authorization_id": "auth-issue-303",
                "invalidated": False,
                "plan_digest": "9" * 64,
                "uses": {},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(LiveStudyAuthorizationError, match="plan"):
        reserve_live_study_authorization_use(
            ledger,
            auth,
            plan_digest=PLAN_DIGEST,
            trial_id=TRIAL_ID,
        )


def test_local_rehearsal_runs_gateway_path_and_keeps_canary_out_of_evidence(
    tmp_path: Path,
) -> None:
    auth = LiveStudyAuthorization(
        data=parse_live_study_authorization(_rehearsal_artifact()),
        digest=live_study_authorization_digest(_rehearsal_artifact()),
    )
    canary = "AGENTGUARD_FAKE_CREDENTIAL_CANARY_303"
    calls = []

    def fake_run(request):
        calls.append("run")
        assert request.preflight_check is not None
        assert request.preflight_check(object())["status"] == "ready"
        assert request.agent_environment_resolver is not None
        assert request.agent_environment_resolver() == {
            "AGENTGUARD_FAKE_API_KEY": canary
        }
        event = evaluate_live_study_egress_destination(
            request.policy,
            host="mock-approved.test",
            port=443,
            protocol="https",
            resolved_addresses=["203.0.113.10"],
        )
        request.evidence_dir.mkdir(parents=True, exist_ok=True)
        (request.evidence_dir / "gateway-evidence.json").write_text(
            json.dumps(
                {
                    "events": [event],
                    "gateway_status": {
                        "status": "running",
                        "evidence_complete": True,
                    },
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        manifest = build_live_study_egress_manifest(
            plan_digest=request.plan_digest,
            profile_hash=request.profile_hash,
            fixture_hash=request.fixture_hash,
            trial_id=request.trial_id,
            policy=request.policy,
            gateway_image={
                "configured_reference": GATEWAY_IMAGE,
                "local_image_id": "sha256:" + "c" * 64,
                "executed_image_id": "sha256:" + "c" * 64,
                "registry_digest": GATEWAY_IMAGE,
                "platform": "linux/amd64",
                "pull_policy": "docker-default",
                "cache_status": "present",
            },
            approved_host="mock-approved.test",
            approved_port=443,
            events=[event],
            gateway_status={"status": "running", "evidence_complete": True},
            cleanup_status={"overall_complete": True},
            liveness_status={"verified": True},
            authorization_id=request.authorization_id,
        )
        manifest_path = request.evidence_dir / "live-study-egress-manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        return LiveStudyEgressTrialResult(
            manifest=manifest,
            manifest_path=manifest_path,
            status="completed",
            outcome="completed",
        )

    result = rehearse_live_study_authorization_locally(
        auth,
        ledger_path=tmp_path / "ledger.json",
        workspace=tmp_path / "workspace",
        evidence_dir=tmp_path / "evidence",
        fake_environment={"AGENTGUARD_FAKE_API_KEY": canary},
        run_trial=fake_run,
    )

    assert calls == ["run"]
    assert result.status == "completed"
    assert result.canary_absent is True
    assert result.gateway_canary_absent is True
    assert canary not in result.manifest_path.read_text(encoding="utf-8")
    assert canary not in result.ledger_path.read_text(encoding="utf-8")


def test_local_rehearsal_invalidates_on_failure_and_rejects_invalid_result(
    tmp_path: Path,
) -> None:
    auth = LiveStudyAuthorization(
        data=parse_live_study_authorization(_rehearsal_artifact()),
        digest=live_study_authorization_digest(_rehearsal_artifact()),
    )

    def bad_result(_request):
        return {"status": "completed"}

    with pytest.raises(LiveStudyAuthorizationError, match="invalid result"):
        rehearse_live_study_authorization_locally(
            auth,
            ledger_path=tmp_path / "ledger.json",
            workspace=tmp_path / "workspace",
            evidence_dir=tmp_path / "evidence",
            fake_environment={"AGENTGUARD_FAKE_API_KEY": "canary"},
            run_trial=bad_result,
        )
    ledger_text = (tmp_path / "ledger.json").read_text(encoding="utf-8")
    assert "invalidated" in ledger_text


def test_local_rehearsal_rejects_canary_leaks(tmp_path: Path) -> None:
    auth = LiveStudyAuthorization(
        data=parse_live_study_authorization(_rehearsal_artifact()),
        digest=live_study_authorization_digest(_rehearsal_artifact()),
    )
    canary = "AGENTGUARD_FAKE_CREDENTIAL_CANARY_LEAK"

    def leaky_run(request):
        request.evidence_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = request.evidence_dir / "live-study-egress-manifest.json"
        manifest_path.write_text(canary, encoding="utf-8")
        return LiveStudyEgressTrialResult(
            manifest={},
            manifest_path=manifest_path,
            status="completed",
            outcome="completed",
        )

    with pytest.raises(LiveStudyAuthorizationError, match="leaked"):
        rehearse_live_study_authorization_locally(
            auth,
            ledger_path=tmp_path / "ledger.json",
            workspace=tmp_path / "workspace",
            evidence_dir=tmp_path / "evidence",
            fake_environment={"AGENTGUARD_FAKE_API_KEY": canary},
            run_trial=leaky_run,
        )


def test_cli_rehearsal_output_does_not_display_canary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    auth_path = tmp_path / "auth.json"
    auth_path.write_text(
        canonical_live_study_authorization(_rehearsal_artifact()) + "\n",
        encoding="utf-8",
    )

    def fake_rehearsal_result(authorization, *, ledger_path, workspace, evidence_dir, fake_environment):
        assert fake_environment == {
            "AGENTGUARD_FAKE_API_KEY": "AGENTGUARD_FAKE_CREDENTIAL_CANARY_1"
        }
        return LiveStudyLocalRehearsalResult(
            status="completed",
            authorization_id="auth-issue-303",
            trial_id=TRIAL_ID,
            manifest_path=evidence_dir / "manifest.json",
            ledger_path=ledger_path,
            canary_absent=True,
            gateway_canary_absent=True,
        )

    monkeypatch.setattr(
        cli_main,
        "rehearse_live_study_authorization_locally",
        fake_rehearsal_result,
    )
    result = runner.invoke(
        app,
        [
            "evaluate",
            "study-auth",
            "rehearse-local",
            str(auth_path),
            "--ledger",
            str(tmp_path / "ledger.json"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Local fake-credential gateway rehearsal complete" in result.output
    assert "AGENTGUARD_FAKE_CREDENTIAL_CANARY" not in result.output
