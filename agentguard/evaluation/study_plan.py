from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from agentguard.evaluation.contained_profile import (
    ContainedAgentProfile,
    contained_agent_profile_diagnostics,
    contained_agent_profile_to_dict,
    load_contained_agent_profile,
)
from agentguard.evaluation.study_fixtures import (
    DEFAULT_STUDY_FIXTURE_MANIFEST,
    StudyFixture,
    StudyFixtureSet,
    load_study_fixture_set,
)
from agentguard.provenance.manifest import sha256_file


CONTAINED_STUDY_PLAN_SCHEMA = "agentguard.contained-study-plan"
CONTAINED_STUDY_PLAN_SCHEMA_VERSION = 1
CONTAINED_STUDY_PROTOCOL_VERSION = "v0.5-preregistered-contained-study"
MAX_STUDY_PLAN_PROFILES = 16
MAX_STUDY_PLAN_TRIALS_PER_UNIT = 100
MAX_STUDY_PLAN_TOTAL_TRIALS = 512


@dataclass(frozen=True)
class ContainedStudyPlanOptions:
    profile_paths: list[Path]
    fixture_set_path: Optional[Path] = None
    fixture_ids: list[str] = field(default_factory=list)
    trials: int = 3


@dataclass(frozen=True)
class ContainedStudyPlan:
    data: dict[str, object]
    digest: str


def build_contained_study_plan(options: ContainedStudyPlanOptions) -> ContainedStudyPlan:
    profile_paths = _validate_profile_paths(options.profile_paths)
    trial_count = _validate_trials(options.trials)
    profiles = [load_contained_agent_profile(path) for path in profile_paths]
    _validate_profiles(profiles)
    fixture_set = load_study_fixture_set(
        options.fixture_set_path or DEFAULT_STUDY_FIXTURE_MANIFEST
    )
    fixtures = _select_fixtures(fixture_set, options.fixture_ids)
    _validate_matrix(profiles, fixtures, trial_count)

    data = _plan_without_digest(profiles, fixture_set, fixtures, trial_count)
    digest = _stable_sha256(data)
    data["plan_digest"] = digest
    return ContainedStudyPlan(data=data, digest=digest)


def serialize_contained_study_plan(plan: ContainedStudyPlan) -> str:
    return _canonical_json(plan.data) + "\n"


def _validate_profile_paths(profile_paths: list[Path]) -> list[Path]:
    if not profile_paths:
        raise ValueError("At least one contained agent profile is required.")
    if len(profile_paths) > MAX_STUDY_PLAN_PROFILES:
        raise ValueError(
            f"Contained study plans support at most {MAX_STUDY_PLAN_PROFILES} profiles."
        )
    resolved = [path.expanduser().resolve() for path in profile_paths]
    if len({str(path) for path in resolved}) != len(resolved):
        raise ValueError("Contained study plan profile paths must be unique.")
    return resolved


def _validate_trials(trials: int) -> int:
    if (
        isinstance(trials, bool)
        or not isinstance(trials, int)
        or trials <= 0
        or trials > MAX_STUDY_PLAN_TRIALS_PER_UNIT
    ):
        raise ValueError(
            "Contained study plan trials must be an integer from 1 to "
            f"{MAX_STUDY_PLAN_TRIALS_PER_UNIT}."
        )
    return trials


def _validate_profiles(profiles: list[ContainedAgentProfile]) -> None:
    profile_ids = [profile.id for profile in profiles]
    if len(set(profile_ids)) != len(profile_ids):
        raise ValueError("Contained study plan profile ids must be unique.")
    for profile in profiles:
        if profile.network != "none":
            raise ValueError(
                "Contained study dry-run plans are offline-only; profile "
                f"{profile.id} requests network mode {profile.network!r}."
            )
        if profile.environment.required:
            raise ValueError(
                "Contained study dry-run plans must not require credentials or "
                f"environment values; profile {profile.id} requires: "
                + ", ".join(profile.environment.required)
            )


def _select_fixtures(
    fixture_set: StudyFixtureSet,
    fixture_ids: list[str],
) -> list[StudyFixture]:
    if len(set(fixture_ids)) != len(fixture_ids):
        raise ValueError("Contained study plan fixture selections must be unique.")
    by_id = {fixture.id: fixture for fixture in fixture_set.fixtures}
    if not fixture_ids:
        return sorted(fixture_set.fixtures, key=lambda fixture: fixture.id)
    missing = sorted(set(fixture_ids) - set(by_id))
    if missing:
        raise ValueError("Unknown contained study fixture id(s): " + ", ".join(missing))
    return [by_id[fixture_id] for fixture_id in sorted(fixture_ids)]


def _validate_matrix(
    profiles: list[ContainedAgentProfile],
    fixtures: list[StudyFixture],
    trials: int,
) -> None:
    if not fixtures:
        raise ValueError("At least one contained study fixture is required.")
    total = len(profiles) * len(fixtures) * trials
    if total > MAX_STUDY_PLAN_TOTAL_TRIALS:
        raise ValueError(
            "Contained study plan is too large: "
            f"{total} trials exceeds {MAX_STUDY_PLAN_TOTAL_TRIALS}."
        )
    for fixture in fixtures:
        if fixture.network_required:
            raise ValueError(
                f"Contained study fixture {fixture.id} requires network access."
            )
    for profile in profiles:
        capabilities = set(profile.capabilities)
        for fixture in fixtures:
            missing = sorted(set(fixture.required_capabilities) - capabilities)
            if missing:
                raise ValueError(
                    f"Profile {profile.id} does not support fixture {fixture.id}; "
                    "missing capabilities: "
                    + ", ".join(missing)
                )


def _plan_without_digest(
    profiles: list[ContainedAgentProfile],
    fixture_set: StudyFixtureSet,
    fixtures: list[StudyFixture],
    trials: int,
) -> dict[str, object]:
    ordered_profiles = sorted(profiles, key=lambda profile: profile.id)
    ordered_fixtures = sorted(fixtures, key=lambda fixture: fixture.id)
    trials_data = []
    trial_ids: set[str] = set()
    for profile in ordered_profiles:
        for fixture in ordered_fixtures:
            for trial_index in range(1, trials + 1):
                trial_id = _trial_id(profile.id, fixture.id, fixture.task_id, trial_index)
                if trial_id in trial_ids:
                    raise ValueError(f"Duplicate contained study trial id: {trial_id}")
                trial_ids.add(trial_id)
                trials_data.append(
                    {
                        "artifact_alias": (
                            "contained-study/"
                            f"{profile.id}/{fixture.id}/trial-{trial_index:03d}"
                        ),
                        "fixture_id": fixture.id,
                        "profile_id": profile.id,
                        "task_id": fixture.task_id,
                        "trial_id": trial_id,
                        "trial_index": trial_index,
                    }
                )
    return {
        "approval_requirements": [
            "No live trial is authorized by this dry-run plan.",
            "Network access, credential names, budgets, final fixture selection, "
            "and public evidence policy require later maintainer approval.",
        ],
        "fixtures": [_fixture_plan_entry(fixture) for fixture in ordered_fixtures],
        "plan_digest": None,
        "profiles": [_profile_plan_entry(profile) for profile in ordered_profiles],
        "protocol_version": CONTAINED_STUDY_PROTOCOL_VERSION,
        "schema": CONTAINED_STUDY_PLAN_SCHEMA,
        "schema_version": CONTAINED_STUDY_PLAN_SCHEMA_VERSION,
        "source_aliases": {
            "fixture_set": "packaged:agentguard.evaluation.study_fixtures.v1",
            "fixture_set_sha256": sha256_file(fixture_set.path),
        },
        "total_planned_trial_count": len(trials_data),
        "trial_repetitions_per_unit": trials,
        "trials": trials_data,
        "warnings": [
            "Dry-run plan only; no agent, container, provider, network, "
            "credential, or subprocess execution was performed.",
            "Docker is an application-level containment boundary for future "
            "approved runs, not an absolute hostile-code sandbox.",
        ],
    }


def _profile_plan_entry(profile: ContainedAgentProfile) -> dict[str, object]:
    diagnostics = contained_agent_profile_diagnostics(profile)
    return {
        "argv": {
            "argc": len(profile.argv),
            "sha256": diagnostics["argv_sha256"],
            "raw_disclosed": False,
        },
        "capabilities": list(profile.capabilities),
        "display_label": profile.display_label,
        "environment": {
            "required": list(profile.environment.required),
            "unset": list(profile.environment.unset),
            "values_recorded": False,
        },
        "id": profile.id,
        "identity": {
            "agent_name": profile.identity.agent_name,
            "agent_version": profile.identity.agent_version,
            "evidence_source": profile.identity.evidence_source,
        },
        "image": profile.image,
        "limits": {
            "cpu_limit": profile.limits.cpu_limit,
            "max_output_bytes": profile.limits.max_output_bytes,
            "memory_limit": profile.limits.memory_limit,
            "pids_limit": profile.limits.pids_limit,
            "timeout_seconds": profile.limits.timeout_seconds,
        },
        "metadata": {
            "max_cost_usd": profile.metadata.max_cost_usd,
            "max_input_tokens": profile.metadata.max_input_tokens,
            "max_output_tokens": profile.metadata.max_output_tokens,
        },
        "network": profile.network,
        "profile_manifest_sha256": _stable_sha256(
            contained_agent_profile_to_dict(profile)
        ),
        "source_alias": f"profiles/{profile.id}.yaml",
    }


def _fixture_plan_entry(fixture: StudyFixture) -> dict[str, object]:
    return {
        "checks": [
            {
                "expected_status": check.expected_status,
                "id": check.id,
                "kind": check.kind,
            }
            for check in fixture.checks
        ],
        "expected": {
            "expected_guard_incidents": list(fixture.expected.expected_guard_incidents),
            "expected_policy_incidents": list(fixture.expected.expected_policy_incidents),
            "functional_success": fixture.expected.functional_success,
            "policy_compliant": fixture.expected.policy_compliant,
            "unsafe_functional_success": fixture.expected.unsafe_functional_success,
        },
        "fixture_hash": fixture.source.hash,
        "id": fixture.id,
        "license": fixture.license,
        "mutation": {
            "allowed_paths": list(fixture.mutation.allowed_paths),
            "forbidden_paths": list(fixture.mutation.forbidden_paths),
            "max_modified_files": fixture.mutation.max_modified_files,
        },
        "network_required": fixture.network_required,
        "prompt_sha256": fixture.prompt.sha256,
        "required_capabilities": list(fixture.required_capabilities),
        "source_alias": f"fixtures/{fixture.id}",
        "task_id": fixture.task_id,
    }


def _trial_id(
    profile_id: str,
    fixture_id: str,
    task_id: str,
    trial_index: int,
) -> str:
    payload = {
        "fixture_id": fixture_id,
        "profile_id": profile_id,
        "task_id": task_id,
        "trial_index": trial_index,
    }
    return "trial-" + _stable_sha256(payload)[:24]


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _stable_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()
