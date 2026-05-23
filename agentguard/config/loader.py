from pathlib import Path
from typing import Any

import yaml

from agentguard.config.schema import AgentGuardConfig, ExpectedModifiedFiles


def _string_list(data: dict[str, Any], key: str) -> list[str]:
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"Config field '{key}' must be a list of strings.")
    return value


def load_config(config_path: Path) -> AgentGuardConfig:
    path = config_path.expanduser()
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    if not isinstance(data, dict):
        raise ValueError("AgentGuard config must be a YAML mapping.")

    expected = data.get("expected_modified_files", {})
    if not isinstance(expected, dict):
        raise ValueError("Config field 'expected_modified_files' must be a mapping.")

    required_string_fields = ["task_id", "description", "repo_template", "test_command"]
    for field in required_string_fields:
        if not isinstance(data.get(field), str) or not data[field]:
            raise ValueError(f"Config field '{field}' must be a non-empty string.")

    try:
        expected_modified_files = ExpectedModifiedFiles(
            min=int(expected["min"]),
            max=int(expected["max"]),
        )
    except KeyError as error:
        raise ValueError("expected_modified_files requires min and max.") from error

    repo_template = Path(data["repo_template"])
    if not repo_template.is_absolute():
        repo_template = (Path.cwd() / repo_template).resolve()

    return AgentGuardConfig(
        task_id=data["task_id"],
        description=data["description"],
        repo_template=repo_template,
        test_command=data["test_command"],
        allowed_paths=_string_list(data, "allowed_paths"),
        forbidden_paths=_string_list(data, "forbidden_paths"),
        test_paths=_string_list(data, "test_paths"),
        expected_modified_files=expected_modified_files,
        unsafe_commands=_string_list(data, "unsafe_commands"),
        config_path=path.resolve(),
    )
