from dataclasses import dataclass
from pathlib import Path
from typing import Optional


VALID_SEVERITIES = {"info", "warning", "error", "critical"}


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
    mode: str = "benchmark"

    def severity_for(self, check_key: str, default: str) -> str:
        return self.policy.get(check_key, default)
