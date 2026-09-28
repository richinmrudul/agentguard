from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from agentguard.io import atomic_write_json


LIVE_STUDY_AUTHORIZATION_SCHEMA = "agentguard.live-study-authorization"
LIVE_STUDY_AUTHORIZATION_SCHEMA_VERSION = 1
MAX_AUTHORIZATION_BYTES = 64 * 1024
MAX_AUTHORIZATION_LIFETIME_SECONDS = 7 * 24 * 60 * 60
MAX_AUTHORIZATION_TRIALS = 512
MAX_AUTHORIZATION_CREDENTIALS = 32
MAX_AUTHORIZATION_DESTINATIONS = 64
MAX_AUTHORIZATION_STRING = 512
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ENV = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
_HOST = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


class LiveStudyAuthorizationError(ValueError):
    pass


@dataclass(frozen=True)
class LiveStudyAuthorization:
    data: dict[str, object]
    digest: str


@dataclass(frozen=True)
class LiveStudyLocalRehearsalResult:
    status: str
    authorization_id: str
    trial_id: str
    manifest_path: Path
    ledger_path: Path
    canary_absent: bool
    gateway_canary_absent: bool
    real_live_execution: str = "unapproved"


def canonical_live_study_authorization(value: dict[str, object]) -> str:
    parsed = parse_live_study_authorization(value)
    return json.dumps(parsed, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def live_study_authorization_digest(value: dict[str, object]) -> str:
    return hashlib.sha256(
        canonical_live_study_authorization(value).encode("utf-8")
    ).hexdigest()


def load_live_study_authorization(path: Path, *, now: Optional[datetime] = None) -> LiveStudyAuthorization:
    try:
        text = path.expanduser().read_text(encoding="utf-8")
    except OSError as error:
        raise LiveStudyAuthorizationError("Live-study authorization is unavailable.") from error
    if len(text.encode("utf-8")) > MAX_AUTHORIZATION_BYTES:
        raise LiveStudyAuthorizationError("Live-study authorization exceeds size bound.")
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as error:
        raise LiveStudyAuthorizationError("Live-study authorization is malformed JSON.") from error
    data = parse_live_study_authorization(raw, now=now)
    canonical = canonical_live_study_authorization(data)
    if text not in {canonical, canonical + "\n"}:
        raise LiveStudyAuthorizationError("Live-study authorization is not canonical.")
    return LiveStudyAuthorization(data=data, digest=_sha256_text(canonical))


def parse_live_study_authorization(
    value: object,
    *,
    now: Optional[datetime] = None,
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise LiveStudyAuthorizationError("Live-study authorization must be an object.")
    allowed = {
        "authorization_id",
        "credential_env_names",
        "destinations",
        "egress_policy_digest",
        "evidence_bounds",
        "expires_at",
        "fixtures",
        "images",
        "issued_at",
        "issuer",
        "limits",
        "max_trial_count",
        "not_before",
        "plan_digest",
        "profile",
        "protocol_version",
        "provider",
        "publication_redaction_policy_digest",
        "schema",
        "schema_version",
        "stop_thresholds",
        "trials",
    }
    _reject_unknown(value, allowed, "authorization")
    if value.get("schema") != LIVE_STUDY_AUTHORIZATION_SCHEMA:
        raise LiveStudyAuthorizationError("Invalid live-study authorization schema.")
    if value.get("schema_version") != LIVE_STUDY_AUTHORIZATION_SCHEMA_VERSION:
        raise LiveStudyAuthorizationError("Unsupported live-study authorization version.")
    data = {
        "authorization_id": _id(value.get("authorization_id"), "authorization_id"),
        "credential_env_names": _env_names(value.get("credential_env_names")),
        "destinations": _destinations(value.get("destinations")),
        "egress_policy_digest": _sha256(value.get("egress_policy_digest"), "egress_policy_digest"),
        "evidence_bounds": _bounds(value.get("evidence_bounds"), "evidence_bounds"),
        "expires_at": _timestamp_string(value.get("expires_at"), "expires_at"),
        "fixtures": _fixtures(value.get("fixtures")),
        "images": _images(value.get("images")),
        "issued_at": _timestamp_string(value.get("issued_at"), "issued_at"),
        "issuer": _bounded_string(value.get("issuer"), "issuer"),
        "limits": _limits(value.get("limits")),
        "max_trial_count": _positive_int(
            value.get("max_trial_count"),
            "max_trial_count",
            maximum=MAX_AUTHORIZATION_TRIALS,
        ),
        "not_before": _timestamp_string(value.get("not_before"), "not_before"),
        "plan_digest": _sha256(value.get("plan_digest"), "plan_digest"),
        "profile": _profile(value.get("profile")),
        "protocol_version": _bounded_string(value.get("protocol_version"), "protocol_version"),
        "provider": _provider(value.get("provider")),
        "publication_redaction_policy_digest": _sha256(
            value.get("publication_redaction_policy_digest"),
            "publication_redaction_policy_digest",
        ),
        "schema": LIVE_STUDY_AUTHORIZATION_SCHEMA,
        "schema_version": LIVE_STUDY_AUTHORIZATION_SCHEMA_VERSION,
        "stop_thresholds": _bounds(value.get("stop_thresholds"), "stop_thresholds"),
        "trials": _trial_ids(value.get("trials")),
    }
    if data["max_trial_count"] != len(data["trials"]):
        raise LiveStudyAuthorizationError("Live-study authorization trial count mismatch.")
    _validate_time_window(data, now=now)
    return data


def validate_live_study_authorization_scope(
    authorization: LiveStudyAuthorization,
    *,
    protocol_version: str,
    plan_digest: str,
    profile_id: str,
    profile_hash: str,
    fixture_id: str,
    fixture_hash: str,
    task_id: str,
    trial_id: str,
    agent_image: str,
    gateway_image: str,
    egress_policy_digest: str,
    destinations: list[dict[str, object]],
    credential_env_names: list[str],
) -> None:
    data = authorization.data
    if data["protocol_version"] != protocol_version:
        raise LiveStudyAuthorizationError("Live-study authorization protocol mismatch.")
    if data["plan_digest"] != plan_digest:
        raise LiveStudyAuthorizationError("Live-study authorization plan mismatch.")
    profile = _as_dict(data["profile"], "profile")
    if profile != {"hash": profile_hash, "id": profile_id}:
        raise LiveStudyAuthorizationError("Live-study authorization profile mismatch.")
    if trial_id not in set(data["trials"]):  # type: ignore[arg-type]
        raise LiveStudyAuthorizationError("Live-study authorization trial mismatch.")
    fixture = {"hash": fixture_hash, "id": fixture_id, "task_id": task_id}
    if fixture not in data["fixtures"]:  # type: ignore[operator]
        raise LiveStudyAuthorizationError("Live-study authorization fixture mismatch.")
    images = _as_dict(data["images"], "images")
    if images.get("agent") != agent_image or images.get("gateway") != gateway_image:
        raise LiveStudyAuthorizationError("Live-study authorization image mismatch.")
    if data["egress_policy_digest"] != egress_policy_digest:
        raise LiveStudyAuthorizationError("Live-study authorization egress policy mismatch.")
    if data["destinations"] != destinations:
        raise LiveStudyAuthorizationError("Live-study authorization destination mismatch.")
    if data["credential_env_names"] != sorted(credential_env_names):
        raise LiveStudyAuthorizationError("Live-study authorization credential mismatch.")


def resolve_authorized_credentials(
    authorization: LiveStudyAuthorization,
    *,
    profile_required_env: list[str],
    environ: dict[str, str],
) -> dict[str, str]:
    names = list(authorization.data["credential_env_names"])  # type: ignore[arg-type]
    if names != sorted(profile_required_env):
        raise LiveStudyAuthorizationError("Authorized credential names do not match profile.")
    resolved = {}
    missing = []
    for name in names:
        value = environ.get(name)
        if value is None or value == "":
            missing.append(name)
        else:
            resolved[name] = value
    if missing:
        raise LiveStudyAuthorizationError(
            "Missing authorized credential environment value(s): " + ", ".join(missing)
        )
    return resolved


def reserve_live_study_authorization_use(
    ledger_path: Path,
    authorization: LiveStudyAuthorization,
    *,
    plan_digest: str,
    trial_id: str,
) -> dict[str, object]:
    return _update_ledger(
        ledger_path,
        authorization,
        plan_digest=plan_digest,
        trial_id=trial_id,
        transition="reserve",
    )


def commit_live_study_authorization_use(
    ledger_path: Path,
    authorization: LiveStudyAuthorization,
    *,
    plan_digest: str,
    trial_id: str,
) -> dict[str, object]:
    return _update_ledger(
        ledger_path,
        authorization,
        plan_digest=plan_digest,
        trial_id=trial_id,
        transition="commit",
    )


def invalidate_live_study_authorization(
    ledger_path: Path,
    authorization: LiveStudyAuthorization,
    *,
    plan_digest: str,
    trial_id: str,
    reason: str,
) -> dict[str, object]:
    state = _update_ledger(
        ledger_path,
        authorization,
        plan_digest=plan_digest,
        trial_id=trial_id,
        transition="invalidate",
    )
    state["invalidated_reason"] = _bounded_string(reason, "invalidated_reason")
    atomic_write_json(ledger_path, state, sort_keys=True)
    return state


def live_study_authorization_status(
    ledger_path: Path,
    authorization: LiveStudyAuthorization,
) -> dict[str, object]:
    state = _load_ledger(ledger_path)
    uses = _as_dict(state.get("uses", {}), "uses")
    auth_uses = [
        value
        for value in uses.values()
        if isinstance(value, dict)
        and value.get("authorization_id") == authorization.data["authorization_id"]
    ]
    return {
        "authorization_id": authorization.data["authorization_id"],
        "digest": authorization.digest,
        "invalidated": state.get("invalidated") is True,
        "recorded_uses": len(auth_uses),
        "real_live_execution": "unapproved",
    }


def rehearse_live_study_authorization_locally(
    authorization: LiveStudyAuthorization,
    *,
    ledger_path: Path,
    workspace: Path,
    evidence_dir: Path,
    fake_environment: dict[str, str],
    run_trial: Optional[Callable[[object], object]] = None,
) -> LiveStudyLocalRehearsalResult:
    from agentguard.evaluation.live_egress_gateway import (
        EgressDestinationRule,
        LiveStudyEgressPolicy,
        LiveStudyEgressTrialRequest,
        LiveStudyEgressTrialResult,
        live_study_egress_policy_digest,
        run_live_study_egress_trial,
    )

    data = authorization.data
    trial_id = str(list(data["trials"])[0])  # type: ignore[arg-type]
    plan_digest = str(data["plan_digest"])
    profile = _as_dict(data["profile"], "profile")
    images = _as_dict(data["images"], "images")
    fixtures = list(data["fixtures"])  # type: ignore[arg-type]
    fixture = _as_dict(fixtures[0], "fixture")
    destinations = list(data["destinations"])  # type: ignore[arg-type]
    policy = LiveStudyEgressPolicy(
        destinations=tuple(
            EgressDestinationRule(
                host=str(destination["host"]),
                port=int(destination["port"]),
                purpose="local authorization rehearsal",
                test_only=True,
            )
            for destination in destinations
        )
    )
    validate_live_study_authorization_scope(
        authorization,
        protocol_version=str(data["protocol_version"]),
        plan_digest=plan_digest,
        profile_id=str(profile["id"]),
        profile_hash=str(profile["hash"]),
        fixture_id=str(fixture["id"]),
        fixture_hash=str(fixture["hash"]),
        task_id=str(fixture["task_id"]),
        trial_id=trial_id,
        agent_image=str(images["agent"]),
        gateway_image=str(images["gateway"]),
        egress_policy_digest=live_study_egress_policy_digest(policy),
        destinations=[{"host": str(item["host"]), "port": int(item["port"])} for item in destinations],
        credential_env_names=list(data["credential_env_names"]),  # type: ignore[arg-type]
    )
    reserve_live_study_authorization_use(
        ledger_path,
        authorization,
        plan_digest=plan_digest,
        trial_id=trial_id,
    )

    def credential_resolver() -> dict[str, str]:
        return resolve_authorized_credentials(
            authorization,
            profile_required_env=list(data["credential_env_names"]),  # type: ignore[arg-type]
            environ=fake_environment,
        )

    def preflight(_plan: object) -> dict[str, object]:
        return {
            "status": "ready",
            "credential_free_mock_connectivity": True,
            "destination_policy_valid": True,
            "docker_plan_valid": True,
            "gateway_identity_valid": True,
            "redaction_canary_ready": True,
        }

    workspace.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    request = LiveStudyEgressTrialRequest(
        plan_digest=plan_digest,
        profile_hash=str(profile["hash"]),
        fixture_hash=str(fixture["hash"]),
        trial_id=trial_id,
        profile_id=str(profile["id"]),
        fixture_id=str(fixture["id"]),
        workspace=workspace,
        evidence_dir=evidence_dir,
        prompt_path=evidence_dir / "local-rehearsal-prompt.txt",
        agent_image=str(images["agent"]),
        agent_command=["proxy-success"],
        agent_environment_names=tuple(data["credential_env_names"]),  # type: ignore[arg-type]
        agent_environment_resolver=credential_resolver,
        authorization_id=str(data["authorization_id"]),
        policy=policy,
        gateway_image=str(images["gateway"]),
        platform="linux-docker-engine-local-rehearsal",
        preflight_check=preflight,
        allow_local_image_id=str(images["agent"]).startswith("sha256:")
        or str(images["gateway"]).startswith("sha256:"),
    )
    executor = run_trial or run_live_study_egress_trial
    try:
        raw_result = executor(request)
        if not isinstance(raw_result, LiveStudyEgressTrialResult):
            raise LiveStudyAuthorizationError("Local authorization rehearsal returned invalid result.")
        result = raw_result
        if result.status == "completed":
            commit_live_study_authorization_use(
                ledger_path,
                authorization,
                plan_digest=plan_digest,
                trial_id=trial_id,
            )
        else:
            invalidate_live_study_authorization(
                ledger_path,
                authorization,
                plan_digest=plan_digest,
                trial_id=trial_id,
                reason=result.outcome,
            )
    except Exception as error:
        try:
            invalidate_live_study_authorization(
                ledger_path,
                authorization,
                plan_digest=plan_digest,
                trial_id=trial_id,
                reason=error.__class__.__name__,
            )
        except LiveStudyAuthorizationError:
            pass
        raise
    canaries = list(fake_environment.values())
    canary_absent = _files_absent(evidence_dir, canaries) and _files_absent(
        ledger_path.parent,
        canaries,
    )
    gateway_canary_absent = _file_absent(evidence_dir / "gateway-evidence.json", canaries)
    if not canary_absent or not gateway_canary_absent:
        raise LiveStudyAuthorizationError("Local authorization rehearsal leaked fake credential canary.")
    return LiveStudyLocalRehearsalResult(
        status=result.status,
        authorization_id=str(data["authorization_id"]),
        trial_id=trial_id,
        manifest_path=result.manifest_path,
        ledger_path=ledger_path,
        canary_absent=canary_absent,
        gateway_canary_absent=gateway_canary_absent,
    )


def _update_ledger(
    ledger_path: Path,
    authorization: LiveStudyAuthorization,
    *,
    plan_digest: str,
    trial_id: str,
    transition: str,
) -> dict[str, object]:
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = ledger_path.with_suffix(ledger_path.suffix + ".lock")
    try:
        descriptor = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise LiveStudyAuthorizationError("Live-study authorization is already in use.") from error
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(str(os.getpid()))
        state = _load_ledger(ledger_path)
        if state.get("invalidated") is True:
            raise LiveStudyAuthorizationError("Live-study authorization has been invalidated.")
        if state.get("authorization_id") not in {None, authorization.data["authorization_id"]}:
            raise LiveStudyAuthorizationError("Live-study authorization ledger identity mismatch.")
        if state.get("plan_digest") not in {None, plan_digest}:
            raise LiveStudyAuthorizationError("Live-study authorization ledger plan mismatch.")
        uses = _as_dict(state.setdefault("uses", {}), "uses")
        key = f"{authorization.data['authorization_id']}:{plan_digest}:{trial_id}"
        current = uses.get(key)
        if transition == "reserve":
            if current is not None:
                raise LiveStudyAuthorizationError("Live-study authorization trial was already used.")
            uses[key] = {
                "authorization_id": authorization.data["authorization_id"],
                "plan_digest": plan_digest,
                "reserved_at": _now_string(),
                "status": "reserved",
                "trial_id": trial_id,
            }
        elif transition == "commit":
            if not isinstance(current, dict) or current.get("status") != "reserved":
                raise LiveStudyAuthorizationError("Live-study authorization use was not reserved.")
            current["committed_at"] = _now_string()
            current["status"] = "committed"
        elif transition == "invalidate":
            state["invalidated"] = True
            state["invalidated_at"] = _now_string()
            if isinstance(current, dict):
                current["status"] = "invalidated"
        else:
            raise AssertionError(transition)
        state.update(
            {
                "authorization_digest": authorization.digest,
                "authorization_id": authorization.data["authorization_id"],
                "plan_digest": plan_digest,
                "schema": "agentguard.live-study-authorization-ledger",
                "schema_version": 1,
                "uses": uses,
            }
        )
        atomic_write_json(ledger_path, state, sort_keys=True)
        return state
    finally:
        try:
            lock_path.unlink()
        except OSError:
            pass


def _load_ledger(path: Path) -> dict[str, object]:
    if not path.exists():
        return {"invalidated": False, "uses": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LiveStudyAuthorizationError("Live-study authorization ledger is unreadable.") from error
    if not isinstance(data, dict):
        raise LiveStudyAuthorizationError("Live-study authorization ledger is malformed.")
    return data


def _files_absent(root: Path, needles: list[str]) -> bool:
    if not needles:
        return True
    if root.is_file():
        return _file_absent(root, needles)
    if not root.exists():
        return True
    try:
        paths = [path for path in root.rglob("*") if path.is_file()]
    except OSError:
        return False
    return all(_file_absent(path, needles) for path in paths)


def _file_absent(path: Path, needles: list[str]) -> bool:
    if not needles or not path.exists() or not path.is_file():
        return True
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return all(needle not in text for needle in needles)


def _validate_time_window(data: dict[str, object], *, now: Optional[datetime]) -> None:
    issued = _parse_time(data["issued_at"], "issued_at")
    not_before = _parse_time(data["not_before"], "not_before")
    expires = _parse_time(data["expires_at"], "expires_at")
    if issued > not_before or not_before >= expires:
        raise LiveStudyAuthorizationError("Live-study authorization timestamp order is invalid.")
    if (expires - not_before).total_seconds() > MAX_AUTHORIZATION_LIFETIME_SECONDS:
        raise LiveStudyAuthorizationError("Live-study authorization lifetime is too long.")
    current = now or datetime.now(timezone.utc)
    if current < not_before:
        raise LiveStudyAuthorizationError("Live-study authorization is not yet valid.")
    if current >= expires:
        raise LiveStudyAuthorizationError("Live-study authorization is expired.")


def _timestamp_string(value: object, label: str) -> str:
    text = _bounded_string(value, label)
    _parse_time(text, label)
    return text


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise LiveStudyAuthorizationError(f"Live-study authorization {label} must be UTC.")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise LiveStudyAuthorizationError(
            f"Live-study authorization {label} timestamp is invalid."
        ) from error
    return parsed


def _fixtures(value: object) -> list[dict[str, object]]:
    raw = _list(value, "fixtures", 1, MAX_AUTHORIZATION_TRIALS)
    fixtures = []
    seen = set()
    for item in raw:
        data = _as_dict(item, "fixture")
        _reject_unknown(data, {"hash", "id", "task_id"}, "fixture")
        fixture = {
            "hash": _sha256(data.get("hash"), "fixture.hash"),
            "id": _id(data.get("id"), "fixture.id"),
            "task_id": _id(data.get("task_id"), "fixture.task_id"),
        }
        key = (fixture["id"], fixture["task_id"], fixture["hash"])
        if key in seen:
            raise LiveStudyAuthorizationError("Duplicate live-study authorization fixture.")
        seen.add(key)
        fixtures.append(fixture)
    return sorted(fixtures, key=lambda item: (str(item["id"]), str(item["task_id"])))


def _profile(value: object) -> dict[str, object]:
    data = _as_dict(value, "profile")
    _reject_unknown(data, {"hash", "id"}, "profile")
    return {
        "hash": _sha256(data.get("hash"), "profile.hash"),
        "id": _id(data.get("id"), "profile.id"),
    }


def _images(value: object) -> dict[str, object]:
    data = _as_dict(value, "images")
    _reject_unknown(data, {"agent", "gateway"}, "images")
    agent = _image(data.get("agent"), "images.agent")
    gateway = _image(data.get("gateway"), "images.gateway")
    return {"agent": agent, "gateway": gateway}


def _image(value: object, label: str) -> str:
    text = _bounded_string(value, label)
    if "@sha256:" not in text and not text.startswith("sha256:"):
        raise LiveStudyAuthorizationError("Live-study authorization image must be immutable.")
    if ":latest" in text:
        raise LiveStudyAuthorizationError("Live-study authorization image must not be mutable.")
    return text


def _provider(value: object) -> dict[str, object]:
    data = _as_dict(value, "provider")
    _reject_unknown(data, {"model_id", "provider_id"}, "provider")
    return {
        "model_id": _id(data.get("model_id"), "provider.model_id"),
        "provider_id": _id(data.get("provider_id"), "provider.provider_id"),
    }


def _limits(value: object) -> dict[str, object]:
    data = _as_dict(value, "limits")
    allowed = {
        "max_turns",
        "per_trial_cost_usd",
        "per_trial_input_tokens",
        "per_trial_output_tokens",
        "per_trial_timeout_seconds",
        "total_cost_usd",
        "total_input_tokens",
        "total_output_tokens",
    }
    _reject_unknown(data, allowed, "limits")
    return {
        "max_turns": _positive_int(data.get("max_turns"), "limits.max_turns", maximum=1000),
        "per_trial_cost_usd": _nonnegative_number(
            data.get("per_trial_cost_usd"),
            "limits.per_trial_cost_usd",
        ),
        "per_trial_input_tokens": _nonnegative_int(
            data.get("per_trial_input_tokens"),
            "limits.per_trial_input_tokens",
            maximum=10_000_000,
        ),
        "per_trial_output_tokens": _nonnegative_int(
            data.get("per_trial_output_tokens"),
            "limits.per_trial_output_tokens",
            maximum=10_000_000,
        ),
        "per_trial_timeout_seconds": _positive_int(
            data.get("per_trial_timeout_seconds"),
            "limits.per_trial_timeout_seconds",
            maximum=86400,
        ),
        "total_cost_usd": _nonnegative_number(data.get("total_cost_usd"), "limits.total_cost_usd"),
        "total_input_tokens": _nonnegative_int(
            data.get("total_input_tokens"),
            "limits.total_input_tokens",
            maximum=1_000_000_000,
        ),
        "total_output_tokens": _nonnegative_int(
            data.get("total_output_tokens"),
            "limits.total_output_tokens",
            maximum=1_000_000_000,
        ),
    }


def _bounds(value: object, label: str) -> dict[str, object]:
    data = _as_dict(value, label)
    if not data:
        raise LiveStudyAuthorizationError(f"Live-study authorization {label} is empty.")
    parsed = {}
    for key, item in sorted(data.items()):
        parsed[_id(key, f"{label}.key")] = _small_json_value(item, label)
    return parsed


def _small_json_value(value: object, label: str) -> object:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if value < 0 or value > 1_000_000_000:
            raise LiveStudyAuthorizationError(f"Live-study authorization {label} is out of bounds.")
        return value
    if isinstance(value, float):
        if value < 0 or value > 1_000_000:
            raise LiveStudyAuthorizationError(f"Live-study authorization {label} is out of bounds.")
        return round(value, 6)
    if isinstance(value, str):
        return _bounded_string(value, label)
    raise LiveStudyAuthorizationError(f"Live-study authorization {label} has unsupported value.")


def _destinations(value: object) -> list[dict[str, object]]:
    raw = _list(value, "destinations", 1, MAX_AUTHORIZATION_DESTINATIONS)
    destinations = []
    seen = set()
    for item in raw:
        data = _as_dict(item, "destination")
        _reject_unknown(data, {"host", "port"}, "destination")
        host = _host(data.get("host"))
        port = _positive_int(data.get("port"), "destination.port", maximum=65535)
        key = (host, port)
        if key in seen:
            raise LiveStudyAuthorizationError("Duplicate live-study authorization destination.")
        seen.add(key)
        destinations.append({"host": host, "port": port})
    return sorted(destinations, key=lambda item: (str(item["host"]), int(item["port"])))


def _host(value: object) -> str:
    text = _bounded_string(value, "destination.host").lower()
    if "*" in text or text.endswith(".") or _HOST.fullmatch(text) is None:
        raise LiveStudyAuthorizationError("Live-study authorization destination must be exact.")
    return text


def _trial_ids(value: object) -> list[str]:
    trials = [_id(item, "trials") for item in _list(value, "trials", 1, MAX_AUTHORIZATION_TRIALS)]
    if len(set(trials)) != len(trials):
        raise LiveStudyAuthorizationError("Duplicate live-study authorization trial.")
    return sorted(trials)


def _env_names(value: object) -> list[str]:
    names = [
        _env_name(item, "credential_env_names")
        for item in _list(value, "credential_env_names", 0, MAX_AUTHORIZATION_CREDENTIALS)
    ]
    if len(set(names)) != len(names):
        raise LiveStudyAuthorizationError("Duplicate live-study authorization credential name.")
    return sorted(names)


def _env_name(value: object, label: str) -> str:
    text = _bounded_string(value, label)
    if _ENV.fullmatch(text) is None:
        raise LiveStudyAuthorizationError("Live-study authorization credential name is invalid.")
    return text


def _sha256(value: object, label: str) -> str:
    text = _bounded_string(value, label)
    if _SHA256.fullmatch(text) is None:
        raise LiveStudyAuthorizationError(f"Live-study authorization {label} must be sha256.")
    return text


def _id(value: object, label: str) -> str:
    text = _bounded_string(value, label)
    if _ID.fullmatch(text) is None:
        raise LiveStudyAuthorizationError(f"Live-study authorization {label} is invalid.")
    return text


def _positive_int(value: object, label: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > maximum:
        raise LiveStudyAuthorizationError(f"Live-study authorization {label} is out of bounds.")
    return value


def _nonnegative_int(value: object, label: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > maximum:
        raise LiveStudyAuthorizationError(f"Live-study authorization {label} is out of bounds.")
    return value


def _nonnegative_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise LiveStudyAuthorizationError(f"Live-study authorization {label} is invalid.")
    number = float(value)
    if number < 0 or number > 1_000_000:
        raise LiveStudyAuthorizationError(f"Live-study authorization {label} is out of bounds.")
    return round(number, 6)


def _list(value: object, label: str, minimum: int, maximum: int) -> list[object]:
    if not isinstance(value, list) or len(value) < minimum or len(value) > maximum:
        raise LiveStudyAuthorizationError(f"Live-study authorization {label} bound is invalid.")
    return value


def _as_dict(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise LiveStudyAuthorizationError(f"Live-study authorization {label} must be an object.")
    return value


def _reject_unknown(value: dict[str, object], allowed: set[str], label: str) -> None:
    if set(value) - allowed:
        raise LiveStudyAuthorizationError(
            f"Live-study authorization {label} contains unknown field(s)."
        )


def _bounded_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_AUTHORIZATION_STRING:
        raise LiveStudyAuthorizationError(f"Live-study authorization {label} must be bounded.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise LiveStudyAuthorizationError(
            f"Live-study authorization {label} contains control characters."
        )
    if any(marker in value for marker in ("sk-", "Bearer ", "-----BEGIN", "ghp_", "xoxb-")):
        raise LiveStudyAuthorizationError(
            f"Live-study authorization {label} appears to contain a credential value."
        )
    return value


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _now_string() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
