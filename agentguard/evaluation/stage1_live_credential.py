"""Future live-only credential boundary; no Stage 1 live profile is enabled."""

from __future__ import annotations

import hmac
import os
import re
import secrets
from dataclasses import dataclass
from decimal import Decimal
from typing import Mapping

from agentguard.evaluation.stage1_live_pricing import pricing_policy_digest
from agentguard.evaluation.stage1_metering import MeteringError
from agentguard.evaluation.stage1_study_ledger import StudyLedger


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE = re.compile(r"^ghcr\.io/richinmrudul/agentguard/[a-z0-9-]+@sha256:[0-9a-f]{64}$")
_CREDENTIAL = re.compile(r"^[A-Za-z0-9_\-]{16,512}$")
_APPROVED_REPLACEMENT_SUBJECTS: frozenset[str] = frozenset()


@dataclass(frozen=True)
class LiveBindings:
    authorization_digest: str
    plan_digest: str
    trial_id: str
    profile_digest: str
    pricing_digest: str
    redaction_digest: str
    gateway_image: str
    agent_image: str
    model: str = "gpt-5.2-2025-12-11"
    destination: str = "api.openai.com:443"

    def validate(self) -> None:
        for name in (
            "authorization_digest", "plan_digest", "profile_digest", "pricing_digest",
            "redaction_digest",
        ):
            if not _DIGEST.fullmatch(getattr(self, name)):
                raise MeteringError("live binding digest is invalid")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", self.trial_id):
            raise MeteringError("live trial ID is invalid")
        if self.pricing_digest != pricing_policy_digest():
            raise MeteringError("live pricing-policy binding differs")
        if self.model != "gpt-5.2-2025-12-11" or self.destination != "api.openai.com:443":
            raise MeteringError("live provider binding differs")
        if not _IMAGE.fullmatch(self.gateway_image) or not _IMAGE.fullmatch(self.agent_image):
            raise MeteringError("live images are not immutable GHCR subjects")
        if "stage1-gateway@" in self.gateway_image or "stage1-codex-agent@" in self.agent_image:
            raise MeteringError("old byte-forwarding images cannot meter spending")


def synthetic_trial_token() -> str:
    return secrets.token_urlsafe(48)


def agent_credential_environment(synthetic_token: str) -> dict[str, str]:
    if not isinstance(synthetic_token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{48,128}", synthetic_token):
        raise MeteringError("synthetic trial token is malformed")
    return {"CODEX_API_KEY": synthetic_token}


class LiveCredentialResolver:
    """One-shot resolver; B2 must approve digest subjects before it is usable."""

    def __init__(self, bindings: LiveBindings) -> None:
        bindings.validate()
        self.bindings = bindings
        self._resolved = False

    def resolve(self, expected: LiveBindings, ledger: StudyLedger,
                environment: Mapping[str, str] | None = None) -> str:
        if self._resolved or expected != self.bindings:
            raise MeteringError("live credential binding or budget is invalid")
        self.bindings.validate()
        if self.bindings.gateway_image not in _APPROVED_REPLACEMENT_SUBJECTS or self.bindings.agent_image not in _APPROVED_REPLACEMENT_SUBJECTS:
            raise MeteringError("replacement images have not been approved for live use")
        scope = ledger.scope
        for binding, scope_value in (
            (self.bindings.authorization_digest, scope.authorization_digest),
            (self.bindings.plan_digest, scope.plan_digest),
            (self.bindings.profile_digest, scope.profile_digest),
            (self.bindings.pricing_digest, scope.pricing_digest),
            (self.bindings.redaction_digest, scope.redaction_digest),
            (self.bindings.model, scope.model),
        ):
            if binding != scope_value:
                raise MeteringError("credential and study ledger bindings differ")
        state = ledger.snapshot()
        trial = state["trials"].get(self.bindings.trial_id)
        if not isinstance(trial, dict) or trial["failed"] or trial["pending"]:
            raise MeteringError("trial has no safe remaining budget")
        if any(item["failed"] or item["pending"] for item in state["trials"].values()):
            raise MeteringError("study has an uncertain request")
        study_spent = sum(Decimal(item["charged_usd"]) for item in state["trials"].values())
        if (study_spent >= Decimal(scope.max_study_cost_usd)
                or Decimal(trial["charged_usd"]) >= Decimal(scope.max_trial_cost_usd)
                or trial["generations"] >= scope.max_trial_generations
                or trial["counts"] >= scope.max_trial_counts):
            raise MeteringError("trial has no safe remaining budget")
        values = os.environ if environment is None else environment
        if any(key.lower() == "codex_api_key" and key != "CODEX_API_KEY" for key in values):
            raise MeteringError("provider credential configuration is ambiguous")
        value = os.environ.pop("CODEX_API_KEY", None) if environment is None else values.get("CODEX_API_KEY")
        self._resolved = True
        if not isinstance(value, str) or not _CREDENTIAL.fullmatch(value):
            raise MeteringError("provider credential is missing or malformed")
        return value


def synthetic_token_matches(candidate: str, expected: str) -> bool:
    return isinstance(candidate, str) and isinstance(expected, str) and hmac.compare_digest(candidate, expected)
