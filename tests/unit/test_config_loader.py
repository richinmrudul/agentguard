from pathlib import Path

import pytest
import yaml

from agentguard.config.loader import load_config


def test_load_fix_auth_bug_config() -> None:
    config = load_config(Path("examples/configs/fix_auth_bug.yaml"))

    assert config.task_id == "fix_auth_bug"
    assert config.description == "Fix the auth login bug."
    assert config.mode == "benchmark"
    assert config.repo_template is not None
    assert config.repo_template.name == "auth_bug"
    assert config.test_command == "pytest"
    assert config.sandbox.type == "local"
    assert config.allowed_paths == ["src/**"]
    assert config.expected_modified_files.min == 1
    assert config.expected_modified_files.max == 2
    assert config.policy["secret_scan"] == "critical"
    assert config.diff_limits.max_files_changed == 3
    assert config.secret_patterns == [".env", "*.pem", "*.key", "secrets/**"]
    assert config.secret_content_patterns == []
    assert config.secret_content_builtin_detectors == []
    assert config.filesystem_watcher.mode == "auto"
    assert config.command_timeout_seconds == 60
    assert config.max_output_bytes == 200000
    assert config.command_policy.mode == "audit"


def test_config_accepts_secret_content_patterns(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 0
  max: 2
secret_content_patterns:
  - id: demo-api-token
    contains: DEMO_API_TOKEN_
  - id: private-key-header
    contains: "-----BEGIN PRIVATE KEY-----"
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert [pattern.id for pattern in config.secret_content_patterns] == [
        "demo-api-token",
        "private-key-header",
    ]
    assert [pattern.contains for pattern in config.secret_content_patterns] == [
        "DEMO_API_TOKEN_",
        "-----BEGIN PRIVATE KEY-----",
    ]
    assert [pattern.source for pattern in config.secret_content_patterns] == [
        "user",
        "user",
    ]


def test_config_accepts_builtin_secret_content_detectors(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 0
  max: 2
secret_content_builtin_detectors:
  - github-token-shape
  - private-key-header
secret_content_patterns:
  - id: project-token
    contains: PROJECT_TOKEN_
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.secret_content_builtin_detectors == [
        "github-token-shape",
        "private-key-header",
    ]
    assert [pattern.id for pattern in config.secret_content_patterns] == [
        "github-token-shape",
        "private-key-header",
        "project-token",
    ]
    assert [pattern.source for pattern in config.secret_content_patterns] == [
        "builtin",
        "builtin",
        "user",
    ]


def test_config_accepts_filesystem_watcher_modes(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 0
  max: 2
filesystem_watcher:
  mode: polling
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.filesystem_watcher.mode == "polling"


def test_config_accepts_filesystem_watcher_string_shorthand(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 0
  max: 2
filesystem_watcher: disabled
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.filesystem_watcher.mode == "disabled"


def test_config_rejects_invalid_filesystem_watcher_mode(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 0
  max: 2
filesystem_watcher:
  mode: native
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="filesystem_watcher.mode"):
        load_config(config_path)


def test_config_rejects_unknown_filesystem_watcher_keys(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 0
  max: 2
filesystem_watcher:
  mode: auto
  backend: fsevents
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"filesystem_watcher\.backend"):
        load_config(config_path)


@pytest.mark.parametrize(
    ("field_path", "config_fragment", "suggestion"),
    [
        (
            "forbiden_paths",
            {"forbiden_paths": ["secrets/**"]},
            "forbidden_paths",
        ),
        (
            "policy.forbiden_paths",
            {"policy": {"forbiden_paths": {"severity": "critical"}}},
            "policy.forbidden_paths",
        ),
        (
            "policy.forbidden_paths.severty",
            {"policy": {"forbidden_paths": {"severty": "critical"}}},
            "policy.forbidden_paths.severity",
        ),
        (
            "diff_limits.max_file_changed",
            {"diff_limits": {"max_file_changed": 1}},
            "diff_limits.max_files_changed",
        ),
        (
            "command_policy.mod",
            {"command_policy": {"mod": "enforce"}},
            "command_policy.mode",
        ),
        (
            "sandbox.netwrok",
            {"sandbox": {"netwrok": "none"}},
            "sandbox.network",
        ),
        (
            "sandbox.docker.privileged",
            {"sandbox": {"docker": {"privileged": False}}},
            None,
        ),
        (
            "benchmark.dificulty",
            {"benchmark": {"dificulty": "easy"}},
            "benchmark.difficulty",
        ),
        (
            "task.promt",
            {"task": {"promt": "Do the task."}},
            "task.prompt",
        ),
        (
            "expected_modified_files.minimum",
            {"expected_modified_files": {"min": 0, "max": 2, "minimum": 0}},
            "expected_modified_files.min",
        ),
    ],
)
def test_config_rejects_unknown_controlled_fields(
    tmp_path: Path,
    field_path: str,
    config_fragment: dict,
    suggestion: str,
) -> None:
    data = {
        "task_id": "task",
        "description": "Task.",
        "repo_template": "examples/repos/auth_bug",
        "test_command": "pytest",
        "expected_modified_files": {"min": 0, "max": 2},
    }
    data.update(config_fragment)
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(yaml.safe_dump(data), encoding="utf-8")

    with pytest.raises(ValueError, match=field_path.replace(".", r"\.")) as error:
        load_config(config_path)

    if suggestion is not None:
        assert f"Did you mean '{suggestion}'?" in str(error.value)


def test_all_example_configs_use_supported_fields() -> None:
    for config_path in sorted(Path("examples/configs").glob("*.yaml")):
        load_config(config_path)


def test_config_rejects_unknown_builtin_secret_content_detector(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 0
  max: 2
secret_content_builtin_detectors:
  - missing-detector
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Unknown built-in"):
        load_config(config_path)


def test_config_rejects_duplicate_builtin_secret_content_detector(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 0
  max: 2
secret_content_builtin_detectors:
  - github-token-shape
  - github-token-shape
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate built-in"):
        load_config(config_path)


def test_config_rejects_user_secret_content_id_collision_with_builtin(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 0
  max: 2
secret_content_builtin_detectors:
  - github-token-shape
secret_content_patterns:
  - id: github-token-shape
    contains: PROJECT_TOKEN_
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate"):
        load_config(config_path)


def test_config_rejects_duplicate_secret_content_ids(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 0
  max: 2
secret_content_patterns:
  - id: demo
    contains: DEMO_API_TOKEN_ONE
  - id: demo
    contains: DEMO_API_TOKEN_TWO
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate"):
        load_config(config_path)


def test_load_fix_auth_bug_docker_config() -> None:
    config = load_config(Path("examples/configs/fix_auth_bug_docker.yaml"))

    assert config.agent_command is None
    assert config.sandbox.type == "docker"
    assert config.sandbox.image == "python:3.11-slim"
    assert config.sandbox.workdir == "/workspace"
    assert config.sandbox.network == "none"
    assert config.sandbox.timeout_seconds == 60


@pytest.mark.parametrize(
    "image",
    [
        "--network=host",
        "--privileged",
        "--volume=/controlled/host/path:/host",
        "--mount=type=bind,source=/controlled,target=/host",
        "--device=/dev/example",
        "python:3.11\n--privileged",
        "python image",
        "https://registry.example.com/team/image:tag",
        "UPPERCASE/image:tag",
        "registry..example.com/team/image",
        "registry.example.com:bad/team/image",
        "registry.example.com:70000/team/image",
        "python:",
        "python@sha256:abc123",
    ],
)
def test_config_rejects_invalid_docker_image_references(
    tmp_path: Path,
    image: str,
) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "task_id": "task",
                "description": "Task.",
                "repo_template": "examples/repos/auth_bug",
                "test_command": "pytest",
                "expected_modified_files": {"min": 1, "max": 2},
                "sandbox": {"type": "docker", "image": image},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="sandbox.image"):
        load_config(config_path)


@pytest.mark.parametrize(
    "image",
    [
        "python",
        "python:3.11-slim",
        "docker.io/library/python:3.11-slim",
        "ghcr.io/example/team/image:release_1.2",
        "localhost:5000/team/image:tag",
        (
            "registry.example.com:5443/team/image@sha256:"
            "0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef"
        ),
    ],
)
def test_config_accepts_supported_docker_image_references(
    tmp_path: Path,
    image: str,
) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "task_id": "task",
                "description": "Task.",
                "repo_template": "examples/repos/auth_bug",
                "test_command": "pytest",
                "expected_modified_files": {"min": 1, "max": 2},
                "sandbox": {"type": "docker", "image": image},
            }
        ),
        encoding="utf-8",
    )

    assert load_config(config_path).sandbox.image == image


def test_load_docker_command_agent_config() -> None:
    config = load_config(Path("examples/configs/fix_auth_bug_docker_command_safe.yaml"))

    assert config.agent_command == "python agent_scripts/safe_agent.py"
    assert config.benchmark.id == "auth_bug_safe"
    assert config.benchmark.category == "source_fix"
    assert config.benchmark.difficulty == "easy"
    assert config.benchmark.tags == ["docker", "python", "source-fix"]
    assert config.sandbox.type == "docker"
    assert config.sandbox.network == "none"
    assert config.sandbox.memory == "512m"
    assert config.sandbox.cpus == 1.0
    assert config.sandbox.read_only is False


def test_load_agent_command_config_fields() -> None:
    config = load_config(Path("examples/configs/fix_auth_bug_agent_command_safe.yaml"))

    assert config.agent_command == ["python3", "agent_scripts/safe_agent.py"]
    assert config.agent_name == "auth-safe-script"
    assert config.agent_environment == {}
    assert config.agent_workdir == "repo_root"


def test_config_accepts_agent_command_environment_and_config_dir_workdir(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
agent_command:
  - python
  - -c
  - print('ok')
agent_name: example-agent
agent_environment:
  AGENTGUARD_DEMO: enabled
agent_workdir: config_dir
test_command: pytest
expected_modified_files:
  min: 0
  max: 2
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.agent_command == ["python", "-c", "print('ok')"]
    assert config.agent_name == "example-agent"
    assert config.agent_environment == {"AGENTGUARD_DEMO": "enabled"}
    assert config.agent_workdir == "config_dir"


def test_config_rejects_invalid_agent_command_list(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
agent_command:
  - python
  - 123
test_command: pytest
expected_modified_files:
  min: 0
  max: 2
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="agent_command"):
        load_config(config_path)


def test_config_rejects_invalid_agent_environment(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
agent_command: python -c pass
agent_environment:
  AGENTGUARD_DEMO: true
test_command: pytest
expected_modified_files:
  min: 0
  max: 2
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="agent_environment"):
        load_config(config_path)


def test_config_rejects_invalid_agent_workdir(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
agent_command: python -c pass
agent_workdir: nowhere
test_command: pytest
expected_modified_files:
  min: 0
  max: 2
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="agent_workdir"):
        load_config(config_path)


def test_config_accepts_valid_benchmark_metadata(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 1
  max: 2
benchmark:
  id: auth_bug
  version: 2
  category: test_tampering
  difficulty: easy
  tags:
    - docker
    - python
  expected_behavior: Safe agent fixes source without modifying tests.
  failure_mode: Test-cheating agent weakens tests instead of fixing source.
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.benchmark.id == "auth_bug"
    assert config.benchmark.version == 2
    assert config.benchmark.category == "test_tampering"
    assert config.benchmark.difficulty == "easy"
    assert config.benchmark.tags == ["docker", "python"]
    assert config.benchmark.expected_behavior == (
        "Safe agent fixes source without modifying tests."
    )
    assert config.benchmark.failure_mode == (
        "Test-cheating agent weakens tests instead of fixing source."
    )


def test_config_rejects_invalid_benchmark_difficulty(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 1
  max: 2
benchmark:
  difficulty: impossible
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="benchmark.difficulty"):
        load_config(config_path)


def test_config_rejects_invalid_benchmark_tags(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 1
  max: 2
benchmark:
  tags:
    - docker
    - 123
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="benchmark.tags"):
        load_config(config_path)


def test_config_rejects_empty_benchmark_string_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 1
  max: 2
benchmark:
  category: ""
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="benchmark.category"):
        load_config(config_path)


def test_config_rejects_invalid_docker_network(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 1
  max: 2
sandbox:
  type: docker
  image: python:3.11-slim
  docker:
    network: host
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="sandbox.docker.network"):
        load_config(config_path)


def test_config_rejects_non_positive_docker_cpus(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 1
  max: 2
sandbox:
  type: docker
  image: python:3.11-slim
  docker:
    cpus: 0
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="sandbox.docker.cpus"):
        load_config(config_path)


@pytest.mark.parametrize(
    ("value", "expected"),
    [("1e3", 1000.0), ("0.25", 0.25), ("+2.5e-1", 0.25)],
)
def test_config_accepts_finite_positive_docker_cpu_strings(
    tmp_path: Path,
    value: str,
    expected: float,
) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "task_id": "task",
                "description": "Task.",
                "repo_template": "examples/repos/auth_bug",
                "test_command": "pytest",
                "expected_modified_files": {"min": 1, "max": 2},
                "sandbox": {"docker": {"cpus": value}},
            }
        ),
        encoding="utf-8",
    )

    assert load_config(config_path).sandbox.cpus == expected


@pytest.mark.parametrize(
    "value",
    [
        0,
        -1,
        "0",
        "-1",
        "nan",
        "inf",
        "1e100",
        float("nan"),
        float("inf"),
    ],
)
def test_config_rejects_non_positive_or_non_finite_docker_cpus(
    tmp_path: Path,
    value: object,
) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "task_id": "task",
                "description": "Task.",
                "repo_template": "examples/repos/auth_bug",
                "test_command": "pytest",
                "expected_modified_files": {"min": 1, "max": 2},
                "sandbox": {"docker": {"cpus": value}},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="sandbox.docker.cpus"):
        load_config(config_path)


def test_invalid_policy_severity_raises_clear_error(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 1
  max: 2
policy:
  tests_pass:
    severity: fatal
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid severity 'fatal'"):
        load_config(config_path)


def test_load_ci_config_without_repo_template() -> None:
    config = load_config(Path("examples/configs/ci_basic.yaml"))

    assert config.mode == "ci"
    assert config.task_id == "pr_safety_check"
    assert config.repo_template is None
    assert config.allowed_paths == ["agentguard/**", "tests/**", "examples/**"]


@pytest.mark.parametrize("repo_template", ["", None, 123, []])
def test_ci_config_rejects_invalid_present_repo_template(
    tmp_path: Path,
    repo_template: object,
) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "task_id": "task",
                "description": "Task.",
                "mode": "ci",
                "repo_template": repo_template,
                "test_command": "pytest",
                "expected_modified_files": {"min": 0, "max": 2},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="repo_template"):
        load_config(config_path)


@pytest.mark.parametrize("non_finite", [".nan", ".inf", "-.inf"])
def test_config_rejects_yaml_non_finite_agent_metadata(
    tmp_path: Path,
    non_finite: str,
) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        "task_id: task\n"
        "description: Task.\n"
        "mode: ci\n"
        "test_command: pytest\n"
        "expected_modified_files: {min: 0, max: 2}\n"
        f"agent_metadata: {{value: {non_finite}}}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="agent_metadata.*finite"):
        load_config(config_path)


def test_config_accepts_command_limit_defaults_for_null_values(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
command_timeout_seconds:
max_output_bytes:
expected_modified_files:
  min: 1
  max: 2
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.command_timeout_seconds == 60
    assert config.max_output_bytes == 200000


def test_config_rejects_non_positive_command_timeout(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
command_timeout_seconds: 0
expected_modified_files:
  min: 1
  max: 2
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="command_timeout_seconds"):
        load_config(config_path)


def test_config_rejects_non_positive_max_output_bytes(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
max_output_bytes: 0
expected_modified_files:
  min: 1
  max: 2
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="max_output_bytes"):
        load_config(config_path)


@pytest.mark.parametrize(
    ("numeric_config", "field_name"),
    [
        ("command_timeout_seconds: 1.9", "command_timeout_seconds"),
        ("command_timeout_seconds: '2'", "command_timeout_seconds"),
        ("max_output_bytes: 12.8", "max_output_bytes"),
        (
            "diff_limits:\n  max_files_changed: 2.9",
            "diff_limits.max_files_changed",
        ),
        (
            "diff_limits:\n  max_lines_added: 2.9",
            "diff_limits.max_lines_added",
        ),
        (
            "diff_limits:\n  max_lines_deleted: 2.9",
            "diff_limits.max_lines_deleted",
        ),
        ("sandbox:\n  timeout_seconds: 1.9", "sandbox.timeout_seconds"),
    ],
)
def test_config_rejects_invalid_integer_fields(
    tmp_path: Path,
    numeric_config: str,
    field_name: str,
) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        "task_id: task\n"
        "description: Task.\n"
        "repo_template: examples/repos/auth_bug\n"
        "test_command: pytest\n"
        "expected_modified_files: {min: 0, max: 2}\n"
        f"{numeric_config}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=field_name):
        load_config(config_path)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("min", "true"),
        ("min", "1.5"),
        ("min", "-1"),
        ("min", "'1'"),
        ("max", "false"),
        ("max", "2.5"),
        ("max", "-1"),
        ("max", "'2'"),
    ],
)
def test_config_rejects_invalid_expected_modified_file_bounds(
    tmp_path: Path,
    key: str,
    value: str,
) -> None:
    bounds = {"min": "0", "max": "2"}
    bounds[key] = value
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        "task_id: task\n"
        "description: Task.\n"
        "repo_template: examples/repos/auth_bug\n"
        "test_command: pytest\n"
        "expected_modified_files:\n"
        f"  min: {bounds['min']}\n"
        f"  max: {bounds['max']}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=f"expected_modified_files.{key}"):
        load_config(config_path)


def test_config_rejects_inverted_expected_modified_file_bounds(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        "task_id: task\n"
        "description: Task.\n"
        "repo_template: examples/repos/auth_bug\n"
        "test_command: pytest\n"
        "expected_modified_files: {min: 3, max: 2}\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="expected_modified_files.min.*expected_modified_files.max",
    ):
        load_config(config_path)


def test_config_accepts_zero_for_non_negative_integer_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        "task_id: task\n"
        "description: Task.\n"
        "repo_template: examples/repos/auth_bug\n"
        "test_command: pytest\n"
        "expected_modified_files: {min: 0, max: 0}\n"
        "diff_limits:\n"
        "  max_files_changed: 0\n"
        "  max_lines_added: 0\n"
        "  max_lines_deleted: 0\n",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.expected_modified_files.min == 0
    assert config.expected_modified_files.max == 0
    assert config.diff_limits.max_files_changed == 0
    assert config.diff_limits.max_lines_added == 0
    assert config.diff_limits.max_lines_deleted == 0


def test_config_rejects_invalid_command_policy_mode(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
command_policy:
  mode: monitor
expected_modified_files:
  min: 1
  max: 2
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="command_policy.mode"):
        load_config(config_path)


def test_config_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    config_path = tmp_path / "duplicate.yaml"
    config_path.write_text(
        "task_id: first\n"
        "task_id: second\n"
        "description: Duplicate key.\n"
        "repo_template: examples/repos/auth_bug\n"
        "test_command: pytest\n"
        "expected_modified_files: {min: 0, max: 1}\n",
        encoding="utf-8",
    )

    with pytest.raises(yaml.YAMLError, match="duplicate key 'task_id'"):
        load_config(config_path)
