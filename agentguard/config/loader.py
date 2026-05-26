from pathlib import Path
from typing import Any, Optional

import yaml

from agentguard.config.schema import (
    VALID_SEVERITIES,
    AgentGuardConfig,
    DiffLimits,
    ExpectedModifiedFiles,
    SandboxConfig,
)


def _string_list(data: dict[str, Any], key: str) -> list[str]:
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"Config field '{key}' must be a list of strings.")
    return value


def _optional_int(mapping: dict[str, Any], key: str, field_name: str) -> Optional[int]:
    if key not in mapping:
        return None
    value = mapping[key]
    if isinstance(value, bool):
        raise ValueError(f"Config field '{field_name}.{key}' must be an integer.")
    try:
        number = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"Config field '{field_name}.{key}' must be an integer.") from error
    if number < 0:
        raise ValueError(f"Config field '{field_name}.{key}' must be non-negative.")
    return number


def _load_policy(data: dict[str, Any]) -> dict[str, str]:
    policy = data.get("policy", {})
    if not isinstance(policy, dict):
        raise ValueError("Config field 'policy' must be a mapping.")

    severities: dict[str, str] = {}
    for check_key, check_config in policy.items():
        if not isinstance(check_key, str):
            raise ValueError("Config field 'policy' keys must be strings.")
        if not isinstance(check_config, dict):
            raise ValueError(f"Config field 'policy.{check_key}' must be a mapping.")
        severity = check_config.get("severity")
        if severity is None:
            continue
        if severity not in VALID_SEVERITIES:
            valid = ", ".join(sorted(VALID_SEVERITIES))
            raise ValueError(
                f"Invalid severity '{severity}' for policy.{check_key}.severity. "
                f"Valid severities: {valid}."
            )
        severities[check_key] = severity
    return severities


def _load_diff_limits(data: dict[str, Any]) -> DiffLimits:
    limits = data.get("diff_limits", {})
    if not isinstance(limits, dict):
        raise ValueError("Config field 'diff_limits' must be a mapping.")
    return DiffLimits(
        max_files_changed=_optional_int(limits, "max_files_changed", "diff_limits"),
        max_lines_added=_optional_int(limits, "max_lines_added", "diff_limits"),
        max_lines_deleted=_optional_int(limits, "max_lines_deleted", "diff_limits"),
    )


def _load_sandbox(data: dict[str, Any]) -> SandboxConfig:
    sandbox = data.get("sandbox", {})
    if sandbox is None:
        sandbox = {}
    if not isinstance(sandbox, dict):
        raise ValueError("Config field 'sandbox' must be a mapping.")

    sandbox_type = sandbox.get("type", "local")
    if sandbox_type not in {"local", "docker"}:
        raise ValueError("Config field 'sandbox.type' must be either 'local' or 'docker'.")

    image = sandbox.get("image")
    if image is not None and (not isinstance(image, str) or not image):
        raise ValueError("Config field 'sandbox.image' must be a non-empty string.")
    if sandbox_type == "docker" and image is None:
        raise ValueError("Config field 'sandbox.image' is required for docker sandbox.")

    workdir = sandbox.get("workdir", "/workspace")
    if not isinstance(workdir, str) or not workdir:
        raise ValueError("Config field 'sandbox.workdir' must be a non-empty string.")

    network = sandbox.get("network", "none")
    if not isinstance(network, str) or not network:
        raise ValueError("Config field 'sandbox.network' must be a non-empty string.")

    timeout_seconds = _optional_int(sandbox, "timeout_seconds", "sandbox")
    if timeout_seconds is None:
        timeout_seconds = 60
    if timeout_seconds == 0:
        raise ValueError("Config field 'sandbox.timeout_seconds' must be positive.")

    return SandboxConfig(
        type=sandbox_type,
        image=image,
        workdir=workdir,
        network=network,
        timeout_seconds=timeout_seconds,
    )


def load_config(config_path: Path) -> AgentGuardConfig:
    path = config_path.expanduser()
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    if not isinstance(data, dict):
        raise ValueError("AgentGuard config must be a YAML mapping.")

    expected = data.get("expected_modified_files", {})
    if not isinstance(expected, dict):
        raise ValueError("Config field 'expected_modified_files' must be a mapping.")

    mode = data.get("mode", "benchmark")
    if mode not in {"benchmark", "ci"}:
        raise ValueError("Config field 'mode' must be either 'benchmark' or 'ci'.")

    required_string_fields = ["task_id", "description", "test_command"]
    for field in required_string_fields:
        if not isinstance(data.get(field), str) or not data[field]:
            raise ValueError(f"Config field '{field}' must be a non-empty string.")
    agent_command = data.get("agent_command")
    if agent_command is not None and (
        not isinstance(agent_command, str) or not agent_command
    ):
        raise ValueError("Config field 'agent_command' must be a non-empty string.")
    if mode == "benchmark" and (
        not isinstance(data.get("repo_template"), str) or not data["repo_template"]
    ):
        raise ValueError("Config field 'repo_template' must be a non-empty string.")

    try:
        expected_modified_files = ExpectedModifiedFiles(
            min=int(expected["min"]),
            max=int(expected["max"]),
        )
    except KeyError as error:
        raise ValueError("expected_modified_files requires min and max.") from error

    repo_template = None
    if data.get("repo_template"):
        repo_template = Path(data["repo_template"])
        if not repo_template.is_absolute():
            repo_template = (Path.cwd() / repo_template).resolve()

    return AgentGuardConfig(
        task_id=data["task_id"],
        description=data["description"],
        repo_template=repo_template,
        test_command=data["test_command"],
        agent_command=agent_command,
        allowed_paths=_string_list(data, "allowed_paths"),
        forbidden_paths=_string_list(data, "forbidden_paths"),
        test_paths=_string_list(data, "test_paths"),
        expected_modified_files=expected_modified_files,
        unsafe_commands=_string_list(data, "unsafe_commands"),
        policy=_load_policy(data),
        diff_limits=_load_diff_limits(data),
        secret_patterns=_string_list(data, "secret_patterns"),
        sandbox=_load_sandbox(data),
        config_path=path.resolve(),
        mode=mode,
    )
