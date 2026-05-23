from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ExpectedModifiedFiles:
    min: int
    max: int


@dataclass(frozen=True)
class AgentGuardConfig:
    task_id: str
    description: str
    repo_template: Path
    test_command: str
    allowed_paths: list[str]
    forbidden_paths: list[str]
    test_paths: list[str]
    expected_modified_files: ExpectedModifiedFiles
    unsafe_commands: list[str]
    config_path: Path
