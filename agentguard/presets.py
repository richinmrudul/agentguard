from __future__ import annotations

import json
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

import yaml


DEFAULT_PRESET_NAME = "recommended"
CI_DEFAULT_COMMAND_TIMEOUT_SECONDS = 60
CI_DEFAULT_MAX_OUTPUT_BYTES = 200000


@dataclass(frozen=True)
class CiPresetSettings:
    command_timeout_seconds: int
    max_output_bytes: int
    allowed_paths: tuple[str, ...]
    forbidden_paths: tuple[str, ...]
    test_paths: tuple[str, ...]
    expected_modified_files_min: int
    expected_modified_files_max: int
    unsafe_commands: tuple[str, ...]
    policy_severities: tuple[tuple[str, str], ...]
    max_files_changed: int
    max_lines_added: int
    max_lines_deleted: int
    secret_patterns: tuple[str, ...]
    secret_content_builtin_detectors: tuple[str, ...] = ()

    def as_public_mapping(self) -> dict[str, Any]:
        return {
            "mode": "ci",
            "command_timeout_seconds": self.command_timeout_seconds,
            "max_output_bytes": self.max_output_bytes,
            "allowed_paths": list(self.allowed_paths),
            "forbidden_paths": list(self.forbidden_paths),
            "test_paths": list(self.test_paths),
            "expected_modified_files": {
                "min": self.expected_modified_files_min,
                "max": self.expected_modified_files_max,
            },
            "unsafe_commands": list(self.unsafe_commands),
            "policy": {
                key: {"severity": severity} for key, severity in self.policy_severities
            },
            "diff_limits": {
                "max_files_changed": self.max_files_changed,
                "max_lines_added": self.max_lines_added,
                "max_lines_deleted": self.max_lines_deleted,
            },
            "secret_patterns": list(self.secret_patterns),
            "secret_content_builtin_detectors": list(
                self.secret_content_builtin_detectors
            ),
        }


@dataclass(frozen=True)
class PolicyPreset:
    name: str
    summary: str
    intended_use: str
    validation_posture: str
    requirements: tuple[str, ...]
    limitations: tuple[str, ...]
    settings: CiPresetSettings
    default: bool = False
    posture_rank: int = 0

    def as_public_mapping(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "name": self.name,
            "default": self.default,
            "summary": self.summary,
            "intended_use": self.intended_use,
            "validation_posture": self.validation_posture,
            "requirements": list(self.requirements),
            "limitations": list(self.limitations),
            "suitable_for_untrusted_code": False,
            "execution_boundary": "post-execution CI validation; no execution containment",
            "settings": self.settings.as_public_mapping(),
        }


_COMMON_FORBIDDEN_PATHS = (
    ".env",
    ".env.*",
    "secrets/**",
    "**/*.pem",
    "**/*.key",
)
_COMMON_SECRET_PATTERNS = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "secrets/**",
)
_COMMON_UNSAFE_COMMANDS = ("rm -rf", "curl", "wget", "nc", "chmod 777")
_BALANCED_POLICY = (
    ("tests_pass", "error"),
    ("forbidden_paths", "critical"),
    ("test_tampering", "error"),
    ("unsafe_commands", "critical"),
    ("scope_adherence", "warning"),
    ("diff_size", "warning"),
    ("secret_scan", "critical"),
)
_STRICT_POLICY = tuple(
    (key, "error" if key in {"scope_adherence", "diff_size"} else severity)
    for key, severity in _BALANCED_POLICY
)


PRESETS = (
    PolicyPreset(
        name="minimal",
        summary="Low-friction evidence and validation for trusted local development.",
        intended_use="Trusted local experiments and low-risk development changes.",
        validation_posture=(
            "Runs every CI check with wider file, diff, time, and output bounds; "
            "scope and diff findings remain non-blocking warnings."
        ),
        requirements=("A repository test command that can run on the host.",),
        limitations=(
            "Does not contain test or agent execution.",
            "Not an execution boundary for untrusted or hostile code.",
            "Wider limits can admit changes that recommended or strict would flag.",
        ),
        posture_rank=0,
        settings=CiPresetSettings(
            command_timeout_seconds=120,
            max_output_bytes=400000,
            allowed_paths=("**",),
            forbidden_paths=_COMMON_FORBIDDEN_PATHS,
            test_paths=("tests/**",),
            expected_modified_files_min=0,
            expected_modified_files_max=100,
            unsafe_commands=_COMMON_UNSAFE_COMMANDS,
            policy_severities=_BALANCED_POLICY,
            max_files_changed=100,
            max_lines_added=4000,
            max_lines_deleted=2000,
            secret_patterns=_COMMON_SECRET_PATTERNS,
        ),
    ),
    PolicyPreset(
        name="recommended",
        summary="Balanced post-execution validation for ordinary development and CI.",
        intended_use="Normal Python development and pull-request CI gating.",
        validation_posture=(
            "Phase 44A-compatible limits and severities with blocking correctness, "
            "forbidden-path, test-tampering, unsafe-command, and secret findings."
        ),
        requirements=("A repository test command that can run on the host.",),
        limitations=(
            "Does not contain test or agent execution.",
            "Detects policy findings after changes exist; it cannot make hostile code safe.",
            "Scope and diff-size findings are non-blocking warnings.",
        ),
        default=True,
        posture_rank=1,
        settings=CiPresetSettings(
            command_timeout_seconds=CI_DEFAULT_COMMAND_TIMEOUT_SECONDS,
            max_output_bytes=CI_DEFAULT_MAX_OUTPUT_BYTES,
            allowed_paths=("**",),
            forbidden_paths=_COMMON_FORBIDDEN_PATHS,
            test_paths=("tests/**",),
            expected_modified_files_min=0,
            expected_modified_files_max=50,
            unsafe_commands=_COMMON_UNSAFE_COMMANDS,
            policy_severities=_BALANCED_POLICY,
            max_files_changed=50,
            max_lines_added=2000,
            max_lines_deleted=1000,
            secret_patterns=_COMMON_SECRET_PATTERNS,
        ),
    ),
    PolicyPreset(
        name="strict",
        summary="Tighter blocking post-execution validation for higher-assurance CI.",
        intended_use="Controlled security evaluation and higher-assurance CI gates.",
        validation_posture=(
            "Tightens file, diff, time, and output bounds; makes scope and diff-size "
            "findings blocking; enables supported built-in secret detectors."
        ),
        requirements=(
            "A repository test command that can run on the host within 30 seconds.",
            "Repository-specific review of the tighter thresholds before CI adoption.",
        ),
        limitations=(
            "Does not contain test or agent execution.",
            "Detection occurs after changes exist and cannot prevent host-side effects.",
            "Tighter limits and shape-based detectors can require project-specific tuning.",
        ),
        posture_rank=2,
        settings=CiPresetSettings(
            command_timeout_seconds=30,
            max_output_bytes=100000,
            allowed_paths=("**",),
            forbidden_paths=_COMMON_FORBIDDEN_PATHS,
            test_paths=("tests/**",),
            expected_modified_files_min=0,
            expected_modified_files_max=25,
            unsafe_commands=_COMMON_UNSAFE_COMMANDS,
            policy_severities=_STRICT_POLICY,
            max_files_changed=25,
            max_lines_added=1000,
            max_lines_deleted=500,
            secret_patterns=_COMMON_SECRET_PATTERNS,
            secret_content_builtin_detectors=(
                "github-token-shape",
                "npm-token-shape",
                "private-key-header",
            ),
        ),
    ),
)


def _registry_by_name(presets: tuple[PolicyPreset, ...]) -> Mapping[str, PolicyPreset]:
    registry = {preset.name: preset for preset in presets}
    if len(registry) != len(presets):
        raise ValueError("Preset names must be unique.")
    defaults = [preset.name for preset in presets if preset.default]
    if defaults != [DEFAULT_PRESET_NAME]:
        raise ValueError(
            f"Preset registry must define only {DEFAULT_PRESET_NAME!r} as default."
        )
    return MappingProxyType(registry)


PRESET_REGISTRY = _registry_by_name(PRESETS)


def preset_names() -> tuple[str, ...]:
    return tuple(PRESET_REGISTRY)


def get_preset(name: str) -> PolicyPreset:
    try:
        return PRESET_REGISTRY[name]
    except KeyError as error:
        valid = ", ".join(preset_names())
        raise ValueError(f"Unknown preset {name!r}. Valid presets: {valid}.") from error


def render_preset_text(preset: PolicyPreset) -> str:
    settings = preset.settings.as_public_mapping()
    lines = [
        f"AgentGuard preset: {preset.name}{' (default)' if preset.default else ''}",
        f"Summary: {preset.summary}",
        f"Intended use: {preset.intended_use}",
        f"Validation posture: {preset.validation_posture}",
        "Execution boundary: post-execution CI validation; no execution containment",
        "Suitable for untrusted code: no",
        "Requirements:",
        *(f"- {item}" for item in preset.requirements),
        "Limitations:",
        *(f"- {item}" for item in preset.limitations),
        "CI-consumed settings:",
        yaml.safe_dump(settings, sort_keys=False, allow_unicode=True).rstrip(),
    ]
    return "\n".join(lines)


def render_preset_machine(preset: PolicyPreset, output_format: str) -> str:
    data = preset.as_public_mapping()
    if output_format == "yaml":
        return yaml.safe_dump(data, sort_keys=False, allow_unicode=True).rstrip()
    if output_format == "json":
        return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    raise ValueError("--format must be one of: text, yaml, json.")
