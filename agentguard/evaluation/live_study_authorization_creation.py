from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from typing import Optional

from agentguard.evaluation.live_egress_contract import LIVE_STUDY_EGRESS_EXECUTION_MODE
from agentguard.evaluation.live_egress_gateway import (
    EgressDestinationRule,
    LiveStudyEgressPolicy,
    live_study_egress_policy_digest,
)
from agentguard.evaluation.live_study_authorization import (
    LIVE_STUDY_AUTHORIZATION_SCHEMA,
    LIVE_STUDY_AUTHORIZATION_SCHEMA_VERSION,
    LiveStudyAuthorizationError,
    canonical_live_study_authorization,
    live_study_authorization_digest,
    parse_live_study_authorization,
)
from agentguard.evaluation.study_runner import (
    ContainedStudyRunnerError,
    _load_plan,
    _validate_plan_contract,
)


@dataclass(frozen=True)
class LiveStudyAuthorizationCreateOptions:
    plan_path: Path
    authorization_id: str
    issuer: str
    issued_at: str
    not_before: str
    expires_at: str
    profile_id: str
    fixture_ids: list[str]
    trial_ids: list[str]
    agent_image: str
    gateway_image: str
    destinations: list[tuple[str, int]]
    credential_env_names: list[str]
    provider_id: str
    model_id: str
    limits: dict[str, object]
    evidence_bounds: dict[str, object]
    stop_thresholds: dict[str, object]
    publication_redaction_policy_digest: str
    egress_policy: Optional[LiveStudyEgressPolicy] = None


@dataclass(frozen=True)
class LiveStudyAuthorizationCreation:
    data: dict[str, object]
    canonical_json: str
    digest: str
    egress_policy_digest: str
    plan_digest: str


def create_live_study_authorization(
    options: LiveStudyAuthorizationCreateOptions,
) -> LiveStudyAuthorizationCreation:
    """Create canonical live-study authorization JSON from explicit reviewed inputs."""
    _reject_wildcards(options)
    plan = _load_plan(options.plan_path.expanduser().resolve())
    try:
        plan_digest = _validate_plan_contract(
            plan,
            execution_mode=LIVE_STUDY_EGRESS_EXECUTION_MODE,
        )
    except ContainedStudyRunnerError as error:
        raise LiveStudyAuthorizationError(str(error)) from error
    profile = _select_profile(plan, options.profile_id)
    if profile["image"] != options.agent_image:
        raise LiveStudyAuthorizationError("Live-study authorization agent image mismatch.")
    required_env = sorted(_string_list(_mapping(profile["environment"], "profile.environment").get("required")))
    if sorted(options.credential_env_names) != required_env:
        raise LiveStudyAuthorizationError(
            "Live-study authorization credential names must match the selected profile."
        )
    trials = _select_trials(plan, options.profile_id, options.trial_ids)
    fixtures = _select_fixtures(plan, options.fixture_ids, trials)
    egress_policy = options.egress_policy or _policy_from_destinations(options.destinations)
    _validate_policy_destinations(egress_policy, options.destinations)
    destinations = [
        {"host": host, "port": port}
        for host, port in sorted({(host.lower(), port) for host, port in options.destinations})
    ]
    artifact = {
        "authorization_id": options.authorization_id,
        "credential_env_names": list(options.credential_env_names),
        "destinations": destinations,
        "egress_policy_digest": live_study_egress_policy_digest(egress_policy),
        "evidence_bounds": dict(options.evidence_bounds),
        "expires_at": options.expires_at,
        "fixtures": fixtures,
        "images": {
            "agent": options.agent_image,
            "gateway": options.gateway_image,
        },
        "issued_at": options.issued_at,
        "issuer": options.issuer,
        "limits": dict(options.limits),
        "max_trial_count": len(options.trial_ids),
        "not_before": options.not_before,
        "plan_digest": plan_digest,
        "profile": {
            "hash": profile["profile_manifest_sha256"],
            "id": profile["id"],
        },
        "protocol_version": plan["protocol_version"],
        "provider": {
            "model_id": options.model_id,
            "provider_id": options.provider_id,
        },
        "publication_redaction_policy_digest": options.publication_redaction_policy_digest,
        "schema": LIVE_STUDY_AUTHORIZATION_SCHEMA,
        "schema_version": LIVE_STUDY_AUTHORIZATION_SCHEMA_VERSION,
        "stop_thresholds": dict(options.stop_thresholds),
        "trials": list(options.trial_ids),
    }
    data = parse_live_study_authorization(artifact)
    canonical = canonical_live_study_authorization(data)
    return LiveStudyAuthorizationCreation(
        data=data,
        canonical_json=canonical,
        digest=live_study_authorization_digest(data),
        egress_policy_digest=str(data["egress_policy_digest"]),
        plan_digest=plan_digest,
    )


def _policy_from_destinations(destinations: list[tuple[str, int]]) -> LiveStudyEgressPolicy:
    return LiveStudyEgressPolicy(
        destinations=tuple(
            EgressDestinationRule(host=host, port=port)
            for host, port in sorted({(host.lower(), port) for host, port in destinations})
        )
    )


def _validate_policy_destinations(
    policy: LiveStudyEgressPolicy,
    destinations: list[tuple[str, int]],
) -> None:
    policy_destinations = {
        (rule.host.lower(), rule.port)
        for rule in policy.destinations
    }
    requested_destinations = {(host.lower(), port) for host, port in destinations}
    if policy_destinations != requested_destinations:
        raise LiveStudyAuthorizationError(
            "Live-study authorization egress policy destination mismatch."
        )


def _select_profile(plan: dict[str, object], profile_id: str) -> dict[str, object]:
    matches = [
        _mapping(profile, "profile")
        for profile in _list(plan.get("profiles"), "profiles")
        if _mapping(profile, "profile").get("id") == profile_id
    ]
    if len(matches) != 1:
        raise LiveStudyAuthorizationError("Live-study authorization profile must be explicit.")
    return matches[0]


def _select_trials(
    plan: dict[str, object],
    profile_id: str,
    trial_ids: list[str],
) -> list[dict[str, object]]:
    if not trial_ids:
        raise LiveStudyAuthorizationError("Live-study authorization requires explicit trials.")
    wanted = set(trial_ids)
    if len(wanted) != len(trial_ids):
        raise LiveStudyAuthorizationError("Duplicate live-study authorization trial.")
    selected = []
    for raw in _list(plan.get("trials"), "trials"):
        trial = _mapping(raw, "trial")
        trial_id = trial.get("trial_id")
        if trial_id in wanted:
            if trial.get("profile_id") != profile_id:
                raise LiveStudyAuthorizationError(
                    "Live-study authorization trial profile mismatch."
                )
            selected.append(trial)
    found = {str(trial["trial_id"]) for trial in selected}
    missing = sorted(wanted - found)
    if missing:
        raise LiveStudyAuthorizationError(
            "Unknown live-study authorization trial(s): " + ", ".join(missing)
        )
    return sorted(selected, key=lambda item: str(item["trial_id"]))


def _select_fixtures(
    plan: dict[str, object],
    fixture_ids: list[str],
    trials: list[dict[str, object]],
) -> list[dict[str, object]]:
    if not fixture_ids:
        raise LiveStudyAuthorizationError("Live-study authorization requires explicit fixtures.")
    wanted = set(fixture_ids)
    if len(wanted) != len(fixture_ids):
        raise LiveStudyAuthorizationError("Duplicate live-study authorization fixture.")
    trial_fixture_ids = {str(trial["fixture_id"]) for trial in trials}
    if wanted != trial_fixture_ids:
        raise LiveStudyAuthorizationError(
            "Live-study authorization fixtures must exactly match the selected trials."
        )
    fixtures_by_id = {
        str(fixture["id"]): fixture
        for fixture in (_mapping(raw, "fixture") for raw in _list(plan.get("fixtures"), "fixtures"))
    }
    missing = sorted(wanted - set(fixtures_by_id))
    if missing:
        raise LiveStudyAuthorizationError(
            "Unknown live-study authorization fixture(s): " + ", ".join(missing)
        )
    return [
        {
            "hash": fixtures_by_id[fixture_id]["fixture_hash"],
            "id": fixtures_by_id[fixture_id]["id"],
            "task_id": fixtures_by_id[fixture_id]["task_id"],
        }
        for fixture_id in sorted(wanted)
    ]


def _reject_wildcards(value: object) -> None:
    if isinstance(value, str):
        if "*" in value:
            raise LiveStudyAuthorizationError("Live-study authorization wildcards are not allowed.")
        return
    if is_dataclass(value):
        _reject_wildcards(asdict(value))
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_wildcards(key)
            _reject_wildcards(item)
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            _reject_wildcards(item)


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise LiveStudyAuthorizationError(f"Live-study authorization {label} must be an object.")
    return value


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise LiveStudyAuthorizationError(f"Live-study authorization {label} must be a list.")
    return value


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise LiveStudyAuthorizationError(
            "Live-study authorization credential names must be a string list."
        )
    return list(value)
