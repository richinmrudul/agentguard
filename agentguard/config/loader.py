import math
import re
from pathlib import Path
from typing import Any, Optional, Union

from agentguard.checks.secret_content import BUILTIN_SECRET_CONTENT_DETECTORS
from agentguard.config.guard_ignores import load_guard_ignore_patterns
from agentguard.config.schema import (
    VALID_BENCHMARK_DIFFICULTIES,
    VALID_SEVERITIES,
    AgentGuardConfig,
    BenchmarkMetadata,
    CommandPolicyConfig,
    DiffLimits,
    ExpectedModifiedFiles,
    FilesystemWatcherConfig,
    SandboxConfig,
    ScalarMetadata,
    SecretContentPattern,
    TaskConfig,
)
from agentguard.config.yaml import load_yaml


VALID_DOCKER_NETWORKS = {"none", "bridge"}
VALID_COMMAND_POLICY_MODES = {"audit", "enforce"}
VALID_AGENT_WORKDIRS = {"repo_root", "config_dir"}
VALID_FILESYSTEM_WATCHER_MODES = {"auto", "polling", "disabled"}
MAX_TASK_PROMPT_FILE_BYTES = 65536
MAX_SECRET_CONTENT_PATTERNS = 32
MAX_SECRET_CONTENT_PATTERN_ID_LENGTH = 64
MIN_SECRET_CONTENT_LITERAL_LENGTH = 8
MAX_SECRET_CONTENT_LITERAL_LENGTH = 1024
MAX_SECRET_CONTENT_LITERAL_BYTES = 2048
MAX_SECRET_CONTENT_TOTAL_LITERAL_BYTES = 16384
SECRET_CONTENT_PATTERN_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")


def _string_list(data: dict[str, Any], key: str) -> list[str]:
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"Config field '{key}' must be a list of strings.")
    return value


def _load_secret_content_patterns(
    data: dict[str, Any],
    builtin_ids: list[str],
) -> list[SecretContentPattern]:
    raw_patterns = data.get("secret_content_patterns", [])
    if not isinstance(raw_patterns, list):
        raise ValueError(
            "Config field 'secret_content_patterns' must be a list."
        )
    if len(raw_patterns) + len(builtin_ids) > MAX_SECRET_CONTENT_PATTERNS:
        raise ValueError(
            "Config secret-content detectors exceed the maximum "
            f"of {MAX_SECRET_CONTENT_PATTERNS} detectors."
        )
    patterns: list[SecretContentPattern] = [
        BUILTIN_SECRET_CONTENT_DETECTORS[detector_id]
        for detector_id in builtin_ids
    ]
    seen_ids: set[str] = set(builtin_ids)
    seen_literals: set[str] = set()
    total_literal_bytes = 0
    for index, raw_pattern in enumerate(raw_patterns):
        label = f"secret_content_patterns[{index}]"
        if not isinstance(raw_pattern, dict):
            raise ValueError(f"Config field '{label}' must be an object.")
        unknown = set(raw_pattern) - {"id", "contains"}
        if unknown:
            raise ValueError(
                f"Config field '{label}' contains unsupported key(s): "
                + ", ".join(sorted(str(key) for key in unknown))
            )
        detector_id = raw_pattern.get("id")
        literal = raw_pattern.get("contains")
        if not isinstance(detector_id, str) or not detector_id:
            raise ValueError(f"Config field '{label}.id' is required.")
        detector_label = f"secret-content detector '{detector_id}'"
        if len(detector_id) > MAX_SECRET_CONTENT_PATTERN_ID_LENGTH:
            raise ValueError(f"{detector_label} has an ID that is too long.")
        if SECRET_CONTENT_PATTERN_ID.fullmatch(detector_id) is None:
            raise ValueError(
                f"{detector_label} ID must use lowercase letters, digits, "
                "underscores, hyphens, or periods."
            )
        if detector_id in seen_ids:
            raise ValueError(f"Duplicate {detector_label} ID.")
        if not isinstance(literal, str):
            raise ValueError(f"{detector_label} requires a string 'contains'.")
        if "\0" in literal:
            raise ValueError(f"{detector_label} literal must not contain NUL.")
        if "\n" in literal or "\r" in literal:
            raise ValueError(
                f"{detector_label} literal must fit on one line."
            )
        if not literal.strip():
            raise ValueError(f"{detector_label} literal must not be blank.")
        if len(literal) < MIN_SECRET_CONTENT_LITERAL_LENGTH:
            raise ValueError(f"{detector_label} literal is too short.")
        if len(literal) > MAX_SECRET_CONTENT_LITERAL_LENGTH:
            raise ValueError(f"{detector_label} literal is too long.")
        literal_bytes = len(literal.encode("utf-8"))
        if literal_bytes > MAX_SECRET_CONTENT_LITERAL_BYTES:
            raise ValueError(f"{detector_label} literal is too large.")
        if literal in seen_literals:
            raise ValueError(f"{detector_label} duplicates another literal.")
        total_literal_bytes += literal_bytes
        if total_literal_bytes > MAX_SECRET_CONTENT_TOTAL_LITERAL_BYTES:
            raise ValueError(
                "Config field 'secret_content_patterns' exceeds the total "
                "literal byte limit."
            )
        seen_ids.add(detector_id)
        seen_literals.add(literal)
        patterns.append(
            SecretContentPattern(id=detector_id, contains=literal)
        )
    return patterns


def _load_secret_content_builtin_detectors(data: dict[str, Any]) -> list[str]:
    raw_detectors = data.get("secret_content_builtin_detectors", [])
    if not isinstance(raw_detectors, list) or not all(
        isinstance(item, str) for item in raw_detectors
    ):
        raise ValueError(
            "Config field 'secret_content_builtin_detectors' must be a list "
            "of strings."
        )
    seen: set[str] = set()
    detectors: list[str] = []
    for detector_id in raw_detectors:
        if detector_id not in BUILTIN_SECRET_CONTENT_DETECTORS:
            raise ValueError(
                "Unknown built-in secret-content detector "
                f"'{detector_id}'."
            )
        if detector_id in seen:
            raise ValueError(
                "Duplicate built-in secret-content detector "
                f"'{detector_id}'."
            )
        seen.add(detector_id)
        detectors.append(detector_id)
    return detectors


def _argv_field(
    data: dict[str, Any],
    key: str,
) -> Optional[Union[str, list[str]]]:
    value = data.get(key)
    if value is None:
        return None
    if isinstance(value, str):
        if not value:
            raise ValueError(
                f"Config field '{key}' must be a non-empty string "
                "or a non-empty list of strings."
            )
        return value
    if isinstance(value, list) and value and all(
        isinstance(item, str) and item for item in value
    ):
        return value
    raise ValueError(
        f"Config field '{key}' must be a non-empty string "
        "or a non-empty list of strings."
    )


def _string_mapping(data: dict[str, Any], key: str) -> dict[str, str]:
    value = data.get(key, {})
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"Config field '{key}' must be a mapping of strings.")
    result: dict[str, str] = {}
    for env_key, env_value in value.items():
        if not isinstance(env_key, str) or not isinstance(env_value, str):
            raise ValueError(f"Config field '{key}' must be a mapping of strings.")
        result[env_key] = env_value
    return result


def _metadata_mapping(
    data: dict[str, Any],
    key: str,
) -> dict[str, ScalarMetadata]:
    value = data.get(key, {})
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"Config field '{key}' must be a mapping.")
    result: dict[str, ScalarMetadata] = {}
    for metadata_key, metadata_value in value.items():
        if not isinstance(metadata_key, str) or not metadata_key.strip():
            raise ValueError(
                f"Config field '{key}' keys must be non-empty strings."
            )
        if not isinstance(metadata_value, (str, int, float, bool)):
            raise ValueError(
                f"Config field '{key}' values must be strings, integers, "
                "floats, or booleans."
            )
        if isinstance(metadata_value, float) and not math.isfinite(metadata_value):
            raise ValueError(f"Config field '{key}' float values must be finite.")
        result[metadata_key] = metadata_value
    return result


def _agent_workdir(data: dict[str, Any]) -> str:
    value = data.get("agent_workdir", "repo_root")
    if value not in VALID_AGENT_WORKDIRS:
        valid = ", ".join(sorted(VALID_AGENT_WORKDIRS))
        raise ValueError(f"Config field 'agent_workdir' must be one of: {valid}.")
    return value


def _load_task(data: dict[str, Any], config_path: Path) -> Optional[TaskConfig]:
    raw_task = data.get("task")
    if raw_task is None:
        return None
    if not isinstance(raw_task, dict):
        raise ValueError("Config field 'task' must be a mapping.")
    prompt = raw_task.get("prompt")
    prompt_file = raw_task.get("prompt_file")
    if (prompt is None) == (prompt_file is None):
        raise ValueError(
            "Config field 'task' requires exactly one of prompt or prompt_file."
        )
    if prompt is not None:
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("Config field 'task.prompt' must be a non-empty string.")
        return TaskConfig(prompt=prompt)
    if not isinstance(prompt_file, str) or not prompt_file:
        raise ValueError(
            "Config field 'task.prompt_file' must be a non-empty string."
        )
    config_dir = config_path.expanduser().resolve().parent
    resolved = (config_dir / prompt_file).resolve()
    try:
        resolved.relative_to(config_dir)
    except ValueError as error:
        raise ValueError(
            "Config field 'task.prompt_file' must stay within the config directory."
        ) from error
    if not resolved.is_file():
        raise ValueError(f"Task prompt file does not exist: {resolved}")
    if resolved.stat().st_size > MAX_TASK_PROMPT_FILE_BYTES:
        raise ValueError(
            "Task prompt file exceeds "
            f"{MAX_TASK_PROMPT_FILE_BYTES} byte limit: {resolved}"
        )
    return TaskConfig(prompt_file=resolved)


def _optional_int(mapping: dict[str, Any], key: str, field_name: str) -> Optional[int]:
    if key not in mapping:
        return None
    value = mapping[key]
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"Config field '{field_name}.{key}' must be an integer.")
    try:
        number = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"Config field '{field_name}.{key}' must be an integer.") from error
    if number < 0:
        raise ValueError(f"Config field '{field_name}.{key}' must be non-negative.")
    return number


def _positive_int_with_default(
    mapping: dict[str, Any],
    key: str,
    field_name: str,
    default: int,
) -> int:
    value = _optional_int(mapping, key, field_name)
    if value is None:
        return default
    if value == 0:
        qualified = key if field_name == "config" else f"{field_name}.{key}"
        raise ValueError(f"Config field '{qualified}' must be positive.")
    return value


def _optional_positive_float(
    mapping: dict[str, Any],
    key: str,
    field_name: str,
) -> Optional[float]:
    if key not in mapping:
        return None
    value = mapping[key]
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"Config field '{field_name}.{key}' must be positive.")
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"Config field '{field_name}.{key}' must be positive.") from error
    if number <= 0:
        raise ValueError(f"Config field '{field_name}.{key}' must be positive.")
    return number


def _optional_non_empty_string(
    mapping: dict[str, Any],
    key: str,
    field_name: str,
) -> Optional[str]:
    if key not in mapping:
        return None
    value = mapping[key]
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"Config field '{field_name}.{key}' must be a non-empty string.")
    return value


def _benchmark_string(
    mapping: dict[str, Any],
    key: str,
) -> Optional[str]:
    if key not in mapping:
        return None
    value = mapping[key]
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Config field 'benchmark.{key}' must be a non-empty string.")
    return value


def _benchmark_version(mapping: dict[str, Any]) -> Optional[int]:
    if "version" not in mapping:
        return None
    value = mapping["version"]
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("Config field 'benchmark.version' must be an integer.")
    try:
        version = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "Config field 'benchmark.version' must be an integer."
        ) from error
    if str(value).strip() != str(version):
        raise ValueError("Config field 'benchmark.version' must be an integer.")
    if version <= 0:
        raise ValueError("Config field 'benchmark.version' must be positive.")
    return version


def _load_benchmark_metadata(data: dict[str, Any]) -> BenchmarkMetadata:
    benchmark = data.get("benchmark", {})
    if benchmark is None:
        benchmark = {}
    if not isinstance(benchmark, dict):
        raise ValueError("Config field 'benchmark' must be a mapping.")

    tags = benchmark.get("tags", [])
    if tags is None:
        tags = []
    if not isinstance(tags, list) or not all(
        isinstance(tag, str) and tag.strip() for tag in tags
    ):
        raise ValueError("Config field 'benchmark.tags' must be a list of strings.")

    difficulty = _benchmark_string(benchmark, "difficulty")
    if difficulty is not None and difficulty not in VALID_BENCHMARK_DIFFICULTIES:
        valid = ", ".join(sorted(VALID_BENCHMARK_DIFFICULTIES))
        raise ValueError(f"Config field 'benchmark.difficulty' must be one of: {valid}.")

    return BenchmarkMetadata(
        id=_benchmark_string(benchmark, "id"),
        version=_benchmark_version(benchmark),
        category=_benchmark_string(benchmark, "category"),
        difficulty=difficulty,
        tags=tags,
        expected_behavior=_benchmark_string(benchmark, "expected_behavior"),
        failure_mode=_benchmark_string(benchmark, "failure_mode"),
    )


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


def _load_command_policy(data: dict[str, Any]) -> CommandPolicyConfig:
    command_policy = data.get("command_policy", {})
    if command_policy is None:
        command_policy = {}
    if not isinstance(command_policy, dict):
        raise ValueError("Config field 'command_policy' must be a mapping.")
    mode = command_policy.get("mode", "audit")
    if mode not in VALID_COMMAND_POLICY_MODES:
        valid = ", ".join(sorted(VALID_COMMAND_POLICY_MODES))
        raise ValueError(f"Config field 'command_policy.mode' must be one of: {valid}.")
    return CommandPolicyConfig(mode=mode)


def _load_filesystem_watcher(data: dict[str, Any]) -> FilesystemWatcherConfig:
    raw = data.get("filesystem_watcher", {})
    if raw is None:
        raw = {}
    if isinstance(raw, str):
        raw = {"mode": raw}
    if not isinstance(raw, dict):
        raise ValueError("Config field 'filesystem_watcher' must be an object.")
    unknown = set(raw) - {"mode"}
    if unknown:
        raise ValueError(
            "Config field 'filesystem_watcher' contains unsupported key(s): "
            + ", ".join(sorted(str(key) for key in unknown))
        )
    mode = raw.get("mode", "auto")
    if mode not in VALID_FILESYSTEM_WATCHER_MODES:
        raise ValueError(
            "filesystem_watcher.mode must be one of: "
            + ", ".join(sorted(VALID_FILESYSTEM_WATCHER_MODES))
        )
    return FilesystemWatcherConfig(mode=mode)


def _load_sandbox(data: dict[str, Any]) -> SandboxConfig:
    sandbox = data.get("sandbox", {})
    if sandbox is None:
        sandbox = {}
    if not isinstance(sandbox, dict):
        raise ValueError("Config field 'sandbox' must be a mapping.")
    docker_policy = sandbox.get("docker", {})
    if docker_policy is None:
        docker_policy = {}
    if not isinstance(docker_policy, dict):
        raise ValueError("Config field 'sandbox.docker' must be a mapping.")

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

    network = docker_policy.get("network", sandbox.get("network", "none"))
    if network not in VALID_DOCKER_NETWORKS:
        valid = ", ".join(sorted(VALID_DOCKER_NETWORKS))
        raise ValueError(
            f"Config field 'sandbox.docker.network' must be one of: {valid}."
        )

    memory = _optional_non_empty_string(docker_policy, "memory", "sandbox.docker")
    cpus = _optional_positive_float(docker_policy, "cpus", "sandbox.docker")
    read_only = docker_policy.get("read_only", sandbox.get("read_only", False))
    if not isinstance(read_only, bool):
        raise ValueError("Config field 'sandbox.docker.read_only' must be a boolean.")

    timeout_seconds = _positive_int_with_default(
        sandbox,
        "timeout_seconds",
        "sandbox",
        60,
    )

    return SandboxConfig(
        type=sandbox_type,
        image=image,
        workdir=workdir,
        network=network,
        memory=memory,
        cpus=cpus,
        read_only=read_only,
        timeout_seconds=timeout_seconds,
    )


def load_config(config_path: Path) -> AgentGuardConfig:
    path = config_path.expanduser()
    with path.open("r", encoding="utf-8") as file:
        data = load_yaml(file) or {}

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
    agent_command = _argv_field(data, "agent_command")
    agent_name = _optional_non_empty_string(data, "agent_name", "config")
    agent_version_command = _argv_field(data, "agent_version_command")
    agent_model = _optional_non_empty_string(data, "agent_model", "config")
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
            candidates = [Path.cwd() / repo_template]
            candidates.extend(parent / repo_template for parent in path.resolve().parents)
            repo_template = next(
                (candidate for candidate in candidates if candidate.is_dir()),
                path.resolve().parent / repo_template,
            )
        repo_template = repo_template.resolve()

    allowed_paths = _string_list(data, "allowed_paths")
    forbidden_paths = _string_list(data, "forbidden_paths")
    test_paths = _string_list(data, "test_paths")
    secret_patterns = _string_list(data, "secret_patterns")
    secret_content_builtin_detectors = _load_secret_content_builtin_detectors(data)
    secret_content_patterns = _load_secret_content_patterns(
        data,
        secret_content_builtin_detectors,
    )
    guard_ignore_paths = load_guard_ignore_patterns(
        data,
        test_paths=test_paths,
        forbidden_paths=forbidden_paths,
        secret_patterns=secret_patterns,
    )

    return AgentGuardConfig(
        task_id=data["task_id"],
        description=data["description"],
        repo_template=repo_template,
        test_command=data["test_command"],
        agent_command=agent_command,
        agent_name=agent_name,
        agent_environment=_string_mapping(data, "agent_environment"),
        agent_version_command=agent_version_command,
        agent_model=agent_model,
        agent_metadata=_metadata_mapping(data, "agent_metadata"),
        agent_workdir=_agent_workdir(data),
        command_timeout_seconds=_positive_int_with_default(
            data,
            "command_timeout_seconds",
            "config",
            60,
        ),
        max_output_bytes=_positive_int_with_default(
            data,
            "max_output_bytes",
            "config",
            200000,
        ),
        command_policy=_load_command_policy(data),
        filesystem_watcher=_load_filesystem_watcher(data),
        allowed_paths=allowed_paths,
        forbidden_paths=forbidden_paths,
        test_paths=test_paths,
        expected_modified_files=expected_modified_files,
        unsafe_commands=_string_list(data, "unsafe_commands"),
        policy=_load_policy(data),
        diff_limits=_load_diff_limits(data),
        secret_patterns=secret_patterns,
        secret_content_patterns=secret_content_patterns,
        secret_content_builtin_detectors=secret_content_builtin_detectors,
        sandbox=_load_sandbox(data),
        benchmark=_load_benchmark_metadata(data),
        task=_load_task(data, path),
        config_path=path.resolve(),
        mode=mode,
        guard_ignore_paths=guard_ignore_paths,
    )
