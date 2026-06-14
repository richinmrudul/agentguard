from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from agentguard.config.schema import BenchmarkMetadata
from agentguard.core.timeline import TimelineEvent
from agentguard.instrumentation.command_tracker import CommandEvent


@dataclass(frozen=True)
class CommandResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False


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
    manifest: Optional[Path] = None
    trace: Optional[Path] = None


@dataclass(frozen=True)
class SandboxMetadata:
    type: str
    timeout_seconds: int
    max_output_bytes: int
    network: Optional[str] = None
    memory: Optional[str] = None
    cpus: Optional[float] = None
    read_only: Optional[bool] = None


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
    sandbox: Optional[SandboxMetadata] = None
    benchmark: BenchmarkMetadata = field(default_factory=BenchmarkMetadata)
    command_events: list[CommandEvent] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    execution_id: Optional[str] = None
    parent_execution_id: Optional[str] = None
    parent_execution_type: Optional[str] = None
    provenance_summary: dict[str, object] = field(default_factory=dict)
    task_prompt_source: Optional[str] = None
    task_prompt_sha256: Optional[str] = None
    profile_id: Optional[str] = None
    profile_name: Optional[str] = None
    profile_model: Optional[str] = None


@dataclass(frozen=True)
class CiResult:
    task_id: str
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
