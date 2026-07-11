from dataclasses import dataclass, field
from pathlib import Path
from re import Pattern
from typing import Optional, Union


ScalarMetadata = Union[str, int, float, bool]


VALID_SEVERITIES = {"info", "warning", "error", "critical"}
VALID_BENCHMARK_DIFFICULTIES = {"easy", "medium", "hard", "advanced"}


@dataclass(frozen=True)
class BenchmarkMetadata:
    id: Optional[str] = None
    version: Optional[int] = None
    category: Optional[str] = None
    difficulty: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    expected_behavior: Optional[str] = None
    failure_mode: Optional[str] = None

    def has_values(self) -> bool:
        return any(
            [
                self.id,
                self.version,
                self.category,
                self.difficulty,
                self.tags,
                self.expected_behavior,
                self.failure_mode,
            ]
        )


@dataclass(frozen=True)
class ExpectedModifiedFiles:
    min: int
    max: int


@dataclass(frozen=True)
class DiffLimits:
    max_files_changed: Optional[int] = None
    max_lines_added: Optional[int] = None
    max_lines_deleted: Optional[int] = None


@dataclass(frozen=True)
class SecretContentPattern:
    id: str
    contains: Optional[str] = None
    regex: Optional[Pattern[str]] = None
    source: str = "user"


@dataclass(frozen=True)
class SandboxConfig:
    type: str = "local"
    image: Optional[str] = None
    workdir: str = "/workspace"
    network: str = "none"
    memory: Optional[str] = None
    cpus: Optional[float] = None
    read_only: bool = False
    timeout_seconds: int = 60


@dataclass(frozen=True)
class CommandPolicyConfig:
    mode: str = "audit"


@dataclass(frozen=True)
class TaskConfig:
    prompt: Optional[str] = None
    prompt_file: Optional[Path] = None


@dataclass(frozen=True)
class AgentGuardConfig:
    task_id: str
    description: str
    repo_template: Optional[Path]
    test_command: str
    allowed_paths: list[str]
    forbidden_paths: list[str]
    test_paths: list[str]
    expected_modified_files: ExpectedModifiedFiles
    unsafe_commands: list[str]
    policy: dict[str, str]
    diff_limits: DiffLimits
    secret_patterns: list[str]
    config_path: Path
    agent_command: Optional[Union[str, list[str]]] = None
    agent_name: Optional[str] = None
    agent_environment: dict[str, str] = field(default_factory=dict)
    agent_version_command: Optional[Union[str, list[str]]] = None
    agent_model: Optional[str] = None
    agent_metadata: dict[str, ScalarMetadata] = field(default_factory=dict)
    agent_display_command: Optional[list[str]] = None
    agent_workdir_path: Optional[Path] = None
    agent_environment_isolated: bool = False
    agent_workdir: str = "repo_root"
    command_timeout_seconds: int = 60
    max_output_bytes: int = 200000
    command_policy: CommandPolicyConfig = field(default_factory=CommandPolicyConfig)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    benchmark: BenchmarkMetadata = field(default_factory=BenchmarkMetadata)
    task: Optional[TaskConfig] = None
    mode: str = "benchmark"
    guard_ignore_paths: list[str] = field(default_factory=list)
    secret_content_patterns: list[SecretContentPattern] = field(
        default_factory=list
    )
    secret_content_builtin_detectors: list[str] = field(default_factory=list)

    def severity_for(self, check_key: str, default: str) -> str:
        return self.policy.get(check_key, default)
