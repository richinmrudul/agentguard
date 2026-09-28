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
