import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentguard.evaluation.live_study_authorization import (
    LIVE_STUDY_AUTHORIZATION_SCHEMA,
    LIVE_STUDY_AUTHORIZATION_SCHEMA_VERSION,
    LiveStudyAuthorization,
    LiveStudyAuthorizationError,
    canonical_live_study_authorization,
    commit_live_study_authorization_use,
    live_study_authorization_digest,
    live_study_authorization_status,
    load_live_study_authorization,
    parse_live_study_authorization,
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
