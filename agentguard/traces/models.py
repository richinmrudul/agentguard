from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from agentguard.core.result import CheckResult, CommandResult, DiffSummary
from agentguard.instrumentation.command_tracker import CommandEvent


@dataclass(frozen=True)
class ReplayPolicySnapshot:
    enabled_checks: list[str]
    severities: dict[str, str]
    score_weights: dict[str, int]
    forbidden_paths: list[str]
    allowed_paths: list[str]
    test_paths: list[str]
    unsafe_commands: list[str]
    secret_patterns: list[str]
    expected_modified_files_min: int
    expected_modified_files_max: int
    max_files_changed: Optional[int]
    max_lines_added: Optional[int]
    max_lines_deleted: Optional[int]
    command_policy_mode: str
    command_policy_patterns: list[str]
    redacted_inputs: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ReplayEvidence:
    task_id: str
    benchmark_id: Optional[str]
    benchmark_version: Optional[int]
    configuration_hash: str
    test_result: CommandResult
    diff_summary: DiffSummary
    command_events: list[CommandEvent]


@dataclass(frozen=True)
class ReplayCheckComparison:
    name: str
    classification: str
    recorded: Optional[CheckResult]
    recomputed: Optional[CheckResult]
    score_contribution_recorded: Optional[int]
    score_contribution_recomputed: Optional[int]
    differences: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ReplayDivergence:
    field: str
    recorded: object
    recomputed: object
    classification: str


@dataclass(frozen=True)
class ReplayabilityStatus:
    replayable: bool
    supported_checks: list[str]
    missing_inputs: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ReplayReportPaths:
    json: Path
    markdown: Path


@dataclass(frozen=True)
class ReplayResult:
    replay_id: str
    trace_id: str
    trace_schema_version: int
    replayability: ReplayabilityStatus
    original_agentguard_version: str
    replay_agentguard_version: str
    policy_snapshot_hash: Optional[str]
    recorded_checks: list[CheckResult]
    recomputed_checks: list[CheckResult]
    comparisons: list[ReplayCheckComparison]
    recorded_score: int
    recomputed_score: int
    recorded_result: str
    recomputed_result: str
    equivalence: str
    divergences: list[ReplayDivergence]
    source_verification: list[str]
    original_duration_seconds: Optional[float]
    replay_duration_seconds: float
    speedup_ratio: Optional[float]
    no_external_execution: bool
    report_paths: ReplayReportPaths


@dataclass(frozen=True)
class MetamorphicTransformDefinition:
    name: str
    transform_class: str
    description: str
    supported_event_types: list[str]
    expected_effect: str
    deterministic_parameters: dict[str, object] = field(default_factory=dict)
    safety_constraints: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class MetamorphicOutcome:
    result: str
    score: int
    failed_checks: list[str]
    warning_checks: list[str]
    check_statuses: dict[str, bool]
    check_evidence: dict[str, list[str]]


@dataclass(frozen=True)
class MetamorphicCaseResult:
    source_trace: Path
    source_trace_id: Optional[str]
    transform_name: str
    transform_class: str
    trial: int
    transformed_trace_path: Optional[Path]
    transformed_trace_id: Optional[str]
    transformed_root_hash: Optional[str]
    original_outcome: Optional[MetamorphicOutcome]
    transformed_outcome: Optional[MetamorphicOutcome]
    expected_effect: str
    observed_effect: str
    robustness_passed: bool
    replayable: bool
    verification_messages: list[str] = field(default_factory=list)
    failure_reason: Optional[str] = None


@dataclass(frozen=True)
class MetamorphicMetrics:
    traces_tested: int
    transformations_applied: int
    preserving_passed: int
    preserving_failed: int
    changing_detected: int
    changing_failed: int
    invalid_rejected: int
    invalid_failed: int
    per_check_robustness: dict[str, dict[str, int]]
    outcome_stability_rate: Optional[float]
    expected_delta_detection_rate: Optional[float]


@dataclass(frozen=True)
class MetamorphicReportPaths:
    json: Path
    markdown: Path


@dataclass(frozen=True)
class MetamorphicStudyResult:
    study_id: str
    transforms: list[MetamorphicTransformDefinition]
    cases: list[MetamorphicCaseResult]
    metrics: MetamorphicMetrics
    duration_seconds: float
    no_external_execution: bool
    report_paths: MetamorphicReportPaths
