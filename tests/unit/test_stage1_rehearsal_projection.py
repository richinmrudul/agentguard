"""Candidate-only projection proof. No Docker, credential, or network access."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from agentguard.evaluation.live_study_authorization import (
    LiveStudyAuthorization,
    parse_live_study_authorization,
)
from agentguard.evaluation.stage1_credential_broker import binding_for_rehearsal, handoff_request
from agentguard.evaluation.stage1_live_pricing import pricing_policy_digest
from agentguard.evaluation.stage1_metering import canonical_bytes, digest
from agentguard.evaluation.stage1_rehearsal_projection import (
    ProjectionError,
    create_rehearsal_projection,
)
from agentguard.evaluation.stage1_study_ledger import LedgerScope


def SHA(character: str) -> str:
    return "sha256:" + character * 64


NONCE = "9" * 64


def _auth(now: datetime) -> LiveStudyAuthorization:
    def date(delta: int) -> str:
        return (now + timedelta(seconds=delta)).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = parse_live_study_authorization({
        "schema": "agentguard.live-study-authorization", "schema_version": 1,
        "authorization_id": "rehearsal-a", "issuer": "test-only-maintainer",
        "issued_at": date(-60), "not_before": date(-30), "expires_at": date(3600),
        "protocol_version": "v0.5-preregistered-contained-study",
        "credential_env_names": ["CODEX_API_KEY"],
        "destinations": [{"host": "api.openai.com", "port": 443}],
        "egress_policy_digest": "4" * 64,
        "evidence_bounds": {"max_output_bytes": 64000},
        "fixtures": [{"hash": "3" * 64, "id": "fixture-a", "task_id": "taskid-a"}],
        "images": {"agent": SHA("a"), "gateway": SHA("b")},
        "limits": {"max_turns": 2, "per_trial_cost_usd": 1,
                   "per_trial_input_tokens": 30, "per_trial_output_tokens": 20,
                   "per_trial_timeout_seconds": 120, "total_cost_usd": 2,
                   "total_input_tokens": 30, "total_output_tokens": 20},
        "max_trial_count": 1, "plan_digest": "1" * 64,
        "profile": {"hash": "2" * 64, "id": "profile-a"},
        "provider": {"model_id": "gpt-5.2-2025-12-11", "provider_id": "openai-api"},
        "publication_redaction_policy_digest": "5" * 64,
        "stop_thresholds": {"max_failures": 1}, "trials": ["trial-a"],
    }, now=now)
    canonical = json.dumps(data, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return LiveStudyAuthorization(data, hashlib.sha256(canonical.encode()).hexdigest())


def _scope(auth: LiveStudyAuthorization) -> LedgerScope:
    return LedgerScope(
        "sha256:" + auth.digest,
        SHA("1"), SHA("2"), pricing_policy_digest(), SHA("5"),
        "openai-api", "gpt-5.2-2025-12-11", ("trial-a",),
        2, 2, 30, 20, 50, 120, "0.01", "0.02",
    )


def _projection(now: datetime):
    auth = _auth(now)
    return create_rehearsal_projection(
        auth, _scope(auth), trial_id="trial-a", nonce=NONCE,
        gateway_canonical_identity=SHA("c"),
        gateway_binary_digest=SHA("d"), agent_canonical_identity=SHA("e"),
        now_epoch=int(now.timestamp()),
    )


def test_projection_is_deterministic_canonical_and_broker_bound() -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    first = _projection(now)
    second = _projection(now)
    assert first.canonical == second.canonical == canonical_bytes(first.data)
    assert first.digest == second.digest == "sha256:" + hashlib.sha256(first.canonical).hexdigest()
    assert json.loads(first.canonical)["mode"] == "candidate-rehearsal"
    binding = binding_for_rehearsal(first)
    assert binding.projection_digest == first.digest
    assert binding.gateway_binary_digest == SHA("d")
    assert b"CODEX_API_KEY" in handoff_request(binding)


def test_python_projection_matches_maintained_rust_golden_bytes() -> None:
    now = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    generated = _projection(now)
    golden = (Path(__file__).parents[2] / "runtime-images/stage1-metering-rust/tests/fixtures/"
              "rehearsal-projection.json").read_bytes()
    assert generated.canonical == golden
    assert generated.digest == "sha256:de1db6e2dd7152bc911b60ee6a278340a3ddf9b30e4e5cc1ae12d833a4f0bbfd"


@pytest.mark.parametrize("field,bad", [
    ("gateway_canonical_identity", "sha256:" + "A" * 64),
    ("gateway_binary_digest", "bad"),
    ("agent_canonical_identity", "bad"),
    ("nonce", "short"),
])
def test_projection_rejects_invalid_candidate_inputs(field: str, bad: str) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    auth = _auth(now)
    arguments = dict(
        trial_id="trial-a", nonce=NONCE,
        gateway_canonical_identity=SHA("c"), gateway_binary_digest=SHA("d"),
        agent_canonical_identity=SHA("e"), now_epoch=int(now.timestamp()),
    )
    arguments[field] = bad
    with pytest.raises(ProjectionError):
        create_rehearsal_projection(auth, _scope(auth), **arguments)


def test_projection_rejects_ledger_and_authorization_mismatch() -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    auth = _auth(now)
    scope = _scope(auth)
    for changed in (
        replace(scope, max_trial_generations=3),
        replace(scope, max_trial_cost_usd="1.01"),
        replace(scope, plan_digest=SHA("8")),
        replace(scope, profile_digest=SHA("8")),
        replace(scope, redaction_digest=SHA("8")),
    ):
        with pytest.raises(ProjectionError):
            create_rehearsal_projection(
                auth, changed, trial_id="trial-a", nonce=NONCE,
                gateway_canonical_identity=SHA("c"), gateway_binary_digest=SHA("d"),
                agent_canonical_identity=SHA("e"), now_epoch=int(now.timestamp()),
            )
    with pytest.raises(ProjectionError):
        create_rehearsal_projection(
            auth, scope, trial_id="trial-a", nonce=NONCE,
            gateway_canonical_identity=SHA("c"), gateway_binary_digest=SHA("d"),
            agent_canonical_identity=SHA("e"), now_epoch=int(now.timestamp()) + 4000,
        )


def test_projection_mutation_cannot_reuse_digest_or_broker_binding() -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    original = _projection(now)
    for field in ("gateway", "agent", "provider", "authorization", "ledger", "limits"):
        changed = copy.deepcopy(original.data)
        changed[field][next(iter(changed[field]))] = "wrong"
        assert digest(changed) != original.digest
        with pytest.raises(ValueError):
            binding_for_rehearsal(replace(original, data=changed))
