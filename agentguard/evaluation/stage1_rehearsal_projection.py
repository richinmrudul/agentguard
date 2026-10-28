"""Canonical, candidate-only Stage 1 gateway capability projection.

The source authorization remains the authority for plan, fixtures, profile,
images, provider, limits, validity, and credential *name*. The reviewed ledger
scope may only narrow those limits. This module cannot produce a live grant.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal

from agentguard.evaluation.live_study_authorization import (
    LiveStudyAuthorization,
    LiveStudyAuthorizationError,
    parse_live_study_authorization,
)
from agentguard.evaluation.stage1_live_pricing import pricing_policy_digest
from agentguard.evaluation.stage1_metering import canonical_bytes, digest
from agentguard.evaluation.stage1_study_ledger import LedgerScope


SCHEMA = "agentguard.stage1-live-capability-projection"
VERSION = 1
MODE = "candidate-rehearsal"
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[0-9a-f]{64}\Z")
_OPERATIONS = [
    {"method": "POST", "path": "/v1/responses/input_tokens"},
    {"method": "POST", "path": "/v1/responses"},
]


class ProjectionError(ValueError):
    """Sanitized candidate-rehearsal denial."""


@dataclass(frozen=True)
class RehearsalProjection:
    data: dict[str, object]
    canonical: bytes
    digest: str


def _epoch(value: str) -> int:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
            raise ValueError
        return int(parsed.timestamp())
    except (OverflowError, ValueError):
        raise ProjectionError("authorization time is invalid") from None


def create_rehearsal_projection(
    authorization: LiveStudyAuthorization,
    scope: LedgerScope,
    *,
    trial_id: str,
    nonce: str,
    gateway_canonical_identity: str,
    gateway_binary_digest: str,
    agent_canonical_identity: str,
    now_epoch: int | None = None,
) -> RehearsalProjection:
    if not _NONCE.fullmatch(nonce):
        raise ProjectionError("run nonce is invalid")
    for value in (gateway_canonical_identity, gateway_binary_digest, agent_canonical_identity):
        if not _SHA.fullmatch(value):
            raise ProjectionError("candidate identity is invalid")
    current = int(datetime.now(timezone.utc).timestamp()) if now_epoch is None else now_epoch
    if type(current) is not int:
        raise ProjectionError("candidate time is invalid")
    try:
        data = parse_live_study_authorization(
            authorization.data, now=datetime.fromtimestamp(current, timezone.utc),
        )
    except (LiveStudyAuthorizationError, OverflowError, ValueError):
        raise ProjectionError("candidate authorization is invalid") from None
    if authorization.digest != digest_authorization(data):
        raise ProjectionError("authorization digest is invalid")
    provider = data["provider"]
    images = data["images"]
    profile = data["profile"]
    limits = data["limits"]
    fixtures = data["fixtures"]
    if not (isinstance(provider, dict) and isinstance(images, dict)
            and isinstance(profile, dict) and isinstance(limits, dict)
            and isinstance(fixtures, list)):
        raise ProjectionError("candidate authorization structure is invalid")
    matches = [item for item in fixtures if isinstance(item, dict)]
    if (len(matches) != 1 or trial_id not in data["trials"]
            or data["credential_env_names"] != ["CODEX_API_KEY"]
            or data["destinations"] != [{"host": "api.openai.com", "port": 443}]
            or provider != {"provider_id": "openai-api", "model_id": "gpt-5.2-2025-12-11"}
            or not all(isinstance(images.get(role), str)
                       and _SHA.fullmatch(images[role]) for role in ("agent", "gateway"))):
        raise ProjectionError("candidate authorization scope is invalid")
    if (scope.authorization_digest != "sha256:" + authorization.digest
            or scope.plan_digest != "sha256:" + data["plan_digest"]
            or scope.profile_digest != "sha256:" + profile["hash"]
            or scope.redaction_digest != "sha256:" + data["publication_redaction_policy_digest"]
            or scope.pricing_digest != pricing_policy_digest()
            or scope.provider != "openai-api" or scope.model != "gpt-5.2-2025-12-11"
            or tuple(data["trials"]) != scope.trial_ids):
        raise ProjectionError("ledger and authorization do not bind")
    if (scope.max_trial_generations > limits["max_turns"]
            or scope.max_trial_counts < scope.max_trial_generations
            or scope.max_trial_input_tokens > limits["per_trial_input_tokens"]
            or scope.max_trial_output_tokens > limits["per_trial_output_tokens"]
            or scope.max_trial_total_tokens > (
                limits["per_trial_input_tokens"] + limits["per_trial_output_tokens"]
            )
            or scope.max_trial_seconds > limits["per_trial_timeout_seconds"]
            or Decimal(scope.max_trial_cost_usd) > Decimal(str(limits["per_trial_cost_usd"]))
            or Decimal(scope.max_study_cost_usd) > Decimal(str(limits["total_cost_usd"]))):
        raise ProjectionError("ledger exceeds authorization limits")
    start = _epoch(data["not_before"])
    end = _epoch(data["expires_at"])
    if not start <= current < end:
        raise ProjectionError("candidate authorization is not currently valid")
    study_id = "study-" + data["plan_digest"][:24]
    fixture = matches[0]
    projection: dict[str, object] = {
        "schema": SCHEMA, "schema_version": VERSION, "mode": MODE,
        "authorization": {
            "schema": data["schema"], "schema_version": data["schema_version"],
            "digest": "sha256:" + authorization.digest,
            "id": data["authorization_id"],
            "not_before_epoch": start, "expires_at_epoch": end,
        },
        "study_id": study_id, "trial_id": trial_id,
        "replay_id": digest({"authorization_digest": authorization.digest,
                             "trial_id": trial_id, "nonce": nonce}),
        "plan_digest": "sha256:" + data["plan_digest"],
        "profile": {"id": profile["id"], "digest": "sha256:" + profile["hash"]},
        "fixture": {"id": fixture["id"], "digest": "sha256:" + fixture["hash"]},
        "gateway": {
            "publication_state": MODE, "subject": images["gateway"],
            "canonical_identity": gateway_canonical_identity,
            "binary_digest": gateway_binary_digest,
        },
        "agent": {
            "publication_state": MODE, "subject": images["agent"],
            "canonical_identity": agent_canonical_identity,
        },
        "provider": {"id": "openai-api", "model": "gpt-5.2-2025-12-11",
                     "destination": "api.openai.com:443", "operations": _OPERATIONS},
        "credential_env_name": "CODEX_API_KEY",
        "pricing_digest": pricing_policy_digest(),
        "ledger": {"schema": "agentguard.stage1-study-ledger", "schema_version": 1,
                   "scope_digest": digest(vars(scope)), "study_id": study_id},
        "limits": {
            "max_turns": limits["max_turns"],
            "max_generation_requests": scope.max_trial_generations,
            "max_count_requests": scope.max_trial_counts,
            "max_trial_seconds": scope.max_trial_seconds,
            "max_trial_input_tokens": scope.max_trial_input_tokens,
            "max_trial_output_tokens": scope.max_trial_output_tokens,
            "max_trial_total_tokens": scope.max_trial_total_tokens,
            "max_trial_cost_usd": scope.max_trial_cost_usd,
            "max_study_cost_usd": scope.max_study_cost_usd,
        },
        "evidence": {"schema": "agentguard.stage1-metering-evidence", "schema_version": 2},
        "redaction_digest": "sha256:" + data["publication_redaction_policy_digest"],
        "run_nonce": nonce, "broker_protocol_version": 1,
    }
    canonical = canonical_bytes(projection)
    if len(canonical) > 8192:
        raise ProjectionError("projection exceeds size bound")
    return RehearsalProjection(projection, canonical, digest(projection))


def digest_authorization(data: dict[str, object]) -> str:
    canonical = json.dumps(data, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
