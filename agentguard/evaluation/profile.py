import hashlib
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from agentguard.config.loader import _metadata_mapping
from agentguard.config.schema import AgentGuardConfig, ScalarMetadata
from agentguard.provenance.manifest import SECRET_KEY_PATTERN, sanitize_arguments


PROFILE_SCHEMA = "agentguard.agent-profile"
PROFILE_SCHEMA_VERSION = 1
SUPPORTED_PLACEHOLDERS = {"{task_prompt}", "{task_file}", "{repo_dir}"}
PLACEHOLDER_PATTERN = re.compile(r"\{[^{}]+\}")
ENVIRONMENT_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class AgentProfile:
    id: str
    name: str
    command: list[str]
    profile_path: Path
    version_command: Optional[list[str]] = None
    model: Optional[str] = None
    workdir: str = "repo_root"
    environment: list[str] = field(default_factory=list)
    metadata: dict[str, ScalarMetadata] = field(default_factory=dict)
    schema: str = PROFILE_SCHEMA
    schema_version: int = PROFILE_SCHEMA_VERSION


@dataclass(frozen=True)
class TaskPrompt:
    text: str
    source: str
    sha256: str
    prompt_file: Optional[Path] = None


@dataclass(frozen=True)
class RenderedInvocation:
    argv: list[str]
    display_argv: list[str]
    workdir: Path
    environment: dict[str, str]
    task_prompt: TaskPrompt


def _required_string(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Agent profile field '{key}' must be a non-empty string.")
    return value


def _argv_list(data: dict[str, Any], key: str, *, required: bool) -> Optional[list[str]]:
    value = data.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ValueError(
            f"Agent profile field '{key}' must be a non-empty argv list."
        )
    return list(value)


def _validate_placeholders(command: list[str]) -> None:
    for argument in command:
        matches = PLACEHOLDER_PATTERN.findall(argument)
        if not matches:
            continue
        if argument not in SUPPORTED_PLACEHOLDERS:
            if any(match not in SUPPORTED_PLACEHOLDERS for match in matches):
                raise ValueError(f"Unknown agent profile placeholder: {matches[0]}")
            raise ValueError(
                "Agent profile placeholders must occupy a complete argv item."
            )


def load_agent_profile(path: Path) -> AgentProfile:
    profile_path = path.expanduser().resolve()
    with profile_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        raise ValueError("Agent profile must be a YAML mapping.")
    if data.get("schema") != PROFILE_SCHEMA:
        raise ValueError("Invalid agent profile schema.")
    if data.get("schema_version") != PROFILE_SCHEMA_VERSION:
        raise ValueError("Unsupported agent profile schema version.")
    command = _argv_list(data, "command", required=True)
    assert command is not None
    _validate_placeholders(command)
    version_command = _argv_list(data, "version_command", required=False)
    if version_command is not None:
        _validate_placeholders(version_command)
        if any(argument in SUPPORTED_PLACEHOLDERS for argument in version_command):
            raise ValueError("Agent profile version_command cannot use placeholders.")
    workdir = data.get("workdir", "repo_root")
    if workdir not in {"repo_root", "profile_dir"}:
        raise ValueError(
            "Agent profile field 'workdir' must be repo_root or profile_dir."
        )
    environment = data.get("environment", [])
    if not isinstance(environment, list) or not all(
        isinstance(name, str) and ENVIRONMENT_NAME_PATTERN.fullmatch(name)
        for name in environment
    ):
        raise ValueError(
            "Agent profile field 'environment' must contain valid variable names."
        )
    if len(set(environment)) != len(environment):
        raise ValueError("Agent profile environment names must be unique.")
    model = data.get("model")
    if model is not None and (not isinstance(model, str) or not model.strip()):
        raise ValueError("Agent profile field 'model' must be a non-empty string.")
    metadata = _metadata_mapping(data, "metadata")
    sensitive_metadata = [
        key for key in metadata if SECRET_KEY_PATTERN.search(key)
    ]
    if sensitive_metadata:
        raise ValueError(
            "Agent profile metadata cannot use secret-sensitive key(s): "
            + ", ".join(sorted(sensitive_metadata))
        )
    return AgentProfile(
        id=_required_string(data, "id"),
        name=_required_string(data, "name"),
        command=command,
        version_command=version_command,
        model=model,
        workdir=workdir,
        environment=environment,
        metadata=metadata,
        profile_path=profile_path,
    )


def load_task_prompt(config: AgentGuardConfig) -> TaskPrompt:
    if config.task is None:
        raise ValueError(
            f"Benchmark config requires a task prompt for evaluation: {config.config_path}"
        )
    if config.task.prompt is not None:
        text = config.task.prompt
        source = "config"
        prompt_file = None
    else:
        assert config.task.prompt_file is not None
        prompt_file = config.task.prompt_file
        text = prompt_file.read_text(encoding="utf-8")
        source = "file"
    return TaskPrompt(
        text=text,
        source=source,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        prompt_file=prompt_file,
    )


def validate_profile_for_config(
    profile: AgentProfile,
    config: AgentGuardConfig,
) -> TaskPrompt:
    prompt = load_task_prompt(config)
    placeholders = set(profile.command) & SUPPORTED_PLACEHOLDERS
    if "{task_file}" in placeholders and prompt.prompt_file is None:
        raise ValueError(
            f"Profile requires task_file but config uses inline prompt: {config.config_path}"
        )
    return prompt


def missing_environment_names(profile: AgentProfile) -> list[str]:
    return [name for name in profile.environment if name not in os.environ]


def _resolved_executable(
    profile: AgentProfile,
    executable: str,
) -> Optional[str]:
    path = Path(executable).expanduser()
    if path.is_absolute():
        return (
            str(path.resolve())
            if path.is_file() and os.access(path, os.X_OK)
            else None
        )
    has_path_separator = os.sep in executable or (
        os.altsep is not None and os.altsep in executable
    )
    if has_path_separator:
        profile_relative = (profile.profile_path.parent / path).resolve()
        if profile_relative.is_file() and os.access(profile_relative, os.X_OK):
            return str(profile_relative)
    resolved = shutil.which(executable)
    return str(Path(resolved).resolve()) if resolved is not None else None


def resolve_profile_argv(
    profile: AgentProfile,
    command: list[str],
) -> list[str]:
    resolved = _resolved_executable(profile, command[0])
    if resolved is None:
        raise ValueError(f"Agent profile executable is not available: {command[0]}")
    return [resolved, *command[1:]]


def executable_available(profile: AgentProfile) -> bool:
    return _resolved_executable(profile, profile.command[0]) is not None


def version_executable_available(profile: AgentProfile) -> bool:
    if profile.version_command is None:
        return True
    return _resolved_executable(profile, profile.version_command[0]) is not None


def render_invocation(
    profile: AgentProfile,
    config: AgentGuardConfig,
    repo_dir: Path,
) -> RenderedInvocation:
    prompt = validate_profile_for_config(profile, config)
    missing = missing_environment_names(profile)
    if missing:
        raise ValueError(
            "Missing required environment variable(s): " + ", ".join(missing)
        )
    replacements = {
        "{task_prompt}": prompt.text,
        "{task_file}": str(prompt.prompt_file) if prompt.prompt_file else "",
        "{repo_dir}": str(repo_dir.resolve()),
    }
    display_replacements = {
        "{task_prompt}": f"[TASK_PROMPT sha256:{prompt.sha256}]",
        "{task_file}": f"[TASK_FILE sha256:{prompt.sha256}]",
        "{repo_dir}": "[REPO_DIR]",
    }
    argv = resolve_profile_argv(
        profile,
        [replacements.get(argument, argument) for argument in profile.command],
    )
    display_argv = sanitize_arguments(
        [
            display_replacements.get(argument, argument)
            for argument in profile.command
        ],
        [value for value in replacements.values() if value],
    )
    workdir = (
        repo_dir
        if profile.workdir == "repo_root"
        else profile.profile_path.parent
    )
    return RenderedInvocation(
        argv=argv,
        display_argv=display_argv,
        workdir=workdir,
        environment={name: os.environ[name] for name in profile.environment},
        task_prompt=prompt,
    )


def dry_run_invocation(
    profile: AgentProfile,
    config: AgentGuardConfig,
) -> RenderedInvocation:
    prompt = validate_profile_for_config(profile, config)
    argv = sanitize_arguments(
        [
            {
                "{task_prompt}": f"[TASK_PROMPT sha256:{prompt.sha256}]",
                "{task_file}": f"[TASK_FILE sha256:{prompt.sha256}]",
                "{repo_dir}": "[REPO_DIR]",
            }.get(argument, argument)
            for argument in profile.command
        ]
    )
    return RenderedInvocation(
        argv=argv,
        display_argv=argv,
        workdir=Path("[REPO_DIR]" if profile.workdir == "repo_root" else "[PROFILE_DIR]"),
        environment={},
        task_prompt=prompt,
    )
