from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Mapping, Optional

from agentguard.config.schema import ContainedEnvironmentEntry


MAX_CONTAINED_ENVIRONMENT_VALUE_LENGTH = 4096
CONTAINED_ENVIRONMENT_UNSAFE_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
SAFE_RUNTIME_ENVIRONMENT = {
    "HOME": "/tmp/agentguard-home",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
}


@dataclass(frozen=True)
class ContainedEnvironmentDiagnostics:
    supplied: list[str] = field(default_factory=list)
    sensitive: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    defaults: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ResolvedContainedEnvironment:
    values: dict[str, str]
    sensitive_values: list[str]
    diagnostics: ContainedEnvironmentDiagnostics


def resolve_contained_environment(
    entries: list[ContainedEnvironmentEntry],
    *,
    host_environment: Optional[Mapping[str, str]] = None,
) -> ResolvedContainedEnvironment:
    host = os.environ if host_environment is None else host_environment
    values = dict(SAFE_RUNTIME_ENVIRONMENT)
    sensitive_values: list[str] = []
    supplied: list[str] = []
    sensitive: list[str] = []
    missing: list[str] = []
    required_missing: list[str] = []

    for entry in sorted(entries, key=lambda item: item.name):
        if entry.source == "literal":
            value = entry.value
        else:
            value = host.get(entry.name)
        if value is None:
            missing.append(entry.name)
            if entry.required:
                required_missing.append(entry.name)
            continue
        _validate_resolved_value(value, entry.name)
        values[entry.name] = value
        supplied.append(entry.name)
        if entry.sensitive:
            sensitive.append(entry.name)
            sensitive_values.append(value)

    if required_missing:
        raise ValueError(
            "Required contained environment value(s) are missing: "
            + ", ".join(required_missing)
        )
    return ResolvedContainedEnvironment(
        values={key: values[key] for key in sorted(values)},
        sensitive_values=sensitive_values,
        diagnostics=ContainedEnvironmentDiagnostics(
            supplied=supplied,
            sensitive=sensitive,
            missing=missing,
            defaults=sorted(SAFE_RUNTIME_ENVIRONMENT),
        ),
    )


def _validate_resolved_value(value: str, name: str) -> None:
    if len(value) > MAX_CONTAINED_ENVIRONMENT_VALUE_LENGTH:
        raise ValueError(f"Contained environment value for {name} is too long.")
    if CONTAINED_ENVIRONMENT_UNSAFE_CONTROL.search(value) is not None:
        raise ValueError(
            f"Contained environment value for {name} contains an unsafe "
            "control character."
        )
