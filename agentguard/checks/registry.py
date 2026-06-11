from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from agentguard.checks.base import Check
from agentguard.checks.diff_size import DiffSizeCheck
from agentguard.checks.forbidden_paths import ForbiddenPathsCheck
from agentguard.checks.scope_adherence import ScopeAdherenceCheck
from agentguard.checks.secret_scan import SecretScanCheck
from agentguard.checks.test_tampering import TestTamperingCheck
from agentguard.checks.tests_pass import TestsPassCheck
from agentguard.checks.unsafe_commands import UnsafeCommandsCheck


@dataclass(frozen=True)
class CheckRegistration:
    identifier: str
    name: str
    factory: Callable[[], Check]
    policy_check: bool = True


CHECK_REGISTRY = (
    CheckRegistration("tests-passed", "Tests passed", TestsPassCheck, False),
    CheckRegistration("forbidden-paths", "Forbidden paths", ForbiddenPathsCheck),
    CheckRegistration("test-tampering", "Test tampering", TestTamperingCheck),
    CheckRegistration("unsafe-commands", "Unsafe commands", UnsafeCommandsCheck),
    CheckRegistration("scope-adherence", "Scope adherence", ScopeAdherenceCheck),
    CheckRegistration("diff-size", "Diff size", DiffSizeCheck),
    CheckRegistration("secret-scan", "Secret scan", SecretScanCheck),
)


def registered_checks() -> tuple[CheckRegistration, ...]:
    return CHECK_REGISTRY


def registered_check_names() -> tuple[str, ...]:
    return tuple(item.name for item in CHECK_REGISTRY)


def _normalized_check_key(value: str) -> str:
    return "-".join(value.strip().lower().replace("_", "-").split())


def resolve_check_registration(value: str) -> CheckRegistration:
    key = _normalized_check_key(value)
    for registration in CHECK_REGISTRY:
        if key in {
            _normalized_check_key(registration.identifier),
            _normalized_check_key(registration.name),
        }:
            return registration
    raise ValueError(f"Unknown check: {value}")


def normalize_check_selection(
    raw_values: Optional[list[str]],
) -> list[CheckRegistration]:
    if raw_values is None:
        return []
    selected: list[CheckRegistration] = []
    seen: set[str] = set()
    for raw_value in raw_values:
        for value in raw_value.split(","):
            if not value.strip():
                continue
            registration = resolve_check_registration(value)
            if registration.identifier in seen:
                raise ValueError(f"Duplicate check: {registration.name}")
            seen.add(registration.identifier)
            selected.append(registration)
    return selected


def instantiate_checks(
    *,
    disabled_identifiers: Iterable[str] = (),
) -> list[Check]:
    disabled = set(disabled_identifiers)
    unknown = sorted(disabled - {item.identifier for item in CHECK_REGISTRY})
    if unknown:
        raise ValueError(f"Unknown disabled check identifiers: {', '.join(unknown)}")
    return [
        registration.factory()
        for registration in CHECK_REGISTRY
        if registration.identifier not in disabled
    ]
