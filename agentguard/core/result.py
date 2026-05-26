from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from agentguard.core.timeline import TimelineEvent
from agentguard.instrumentation.command_tracker import CommandEvent


@dataclass(frozen=True)
class CommandResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float


@dataclass(frozen=True)
class DiffSummary:
    modified_files: list[str]
    added_files: list[str]
    deleted_files: list[str]
    lines_added: int
    lines_deleted: int
    unified_diff: str

    @property
    def changed_files(self) -> list[str]:
        return self.modified_files + self.added_files + self.deleted_files


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    severity: str
    message: str
    evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ScoreResult:
    result: str
    score: int


@dataclass(frozen=True)
class ReportPaths:
    json: Path
    markdown: Path
    command_log: Optional[Path] = None


@dataclass(frozen=True)
class BenchmarkResult:
    task_id: str
    agent: str
    result: str
    score: int
    config_path: Path
    run_dir: Path
    repo_dir: Path
    test_result: CommandResult
    diff_summary: DiffSummary
    check_results: list[CheckResult]
    report_paths: ReportPaths
    command_events: list[CommandEvent] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)


@dataclass(frozen=True)
class AgentBenchmarkSummary:
    agent: str
    result: str
    score: int
    failed_checks: list[str]
    warning_checks: list[str]
    json_report_path: Path
    markdown_report_path: Path
    run_dir: Path


@dataclass(frozen=True)
class BenchmarkSummaryPaths:
    json: Path
    markdown: Path


@dataclass(frozen=True)
class MultiAgentBenchmarkSummary:
    task_id: str
    config_path: Path
    total_agents: int
    pass_count: int
    fail_count: int
    agents: list[AgentBenchmarkSummary]
    report_paths: BenchmarkSummaryPaths
