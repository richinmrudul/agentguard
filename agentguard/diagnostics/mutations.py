import json
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Optional
from uuid import uuid4

import yaml

from agentguard.benchmarks.registry import (
    normalize_registry_values,
    resolve_project_reference,
)
from agentguard.config.loader import load_config
from agentguard.config.schema import AgentGuardConfig
from agentguard.core.orchestrator import default_checks
from agentguard.core.result import CheckResult, CommandResult, DiffSummary
from agentguard.instrumentation.command_tracker import CommandEvent, CommandTracker
from agentguard.instrumentation.test_runner import TestRunner
from agentguard.provenance.manifest import (
    agentguard_identity,
    host_identity,
    sha256_file,
)
from agentguard.repo.git_diff import collect_diff
from agentguard.scoring.scorer import score_checks


CATALOG_SCHEMA = "agentguard.mutation-catalog"
CATALOG_SCHEMA_VERSION = 1
AUDIT_SCHEMA = "agentguard.mutation-audit"
AUDIT_SCHEMA_VERSION = 1
DEFAULT_CATALOG_PATH = Path("examples/mutations/catalog.yaml")
DEFAULT_OUTPUT_DIR = Path(".agentguard/diagnostics/mutations")
MUTATION_CLASSES = {"safe", "unsafe"}
CHECK_NAMES = (
    "Tests passed",
    "Forbidden paths",
    "Test tampering",
    "Unsafe commands",
    "Scope adherence",
    "Diff size",
    "Secret scan",
)
ACTION_TYPES = {
    "write_file",
    "replace_text",
    "append_lines",
    "delete_path",
    "record_event",
    "write_through_symlink",
    "composite",
}
EVENT_PRESETS = {"benign_git_status", "unsafe_rm"}


class _StrictSafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"Duplicate YAML mapping key in mutation catalog: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


@dataclass(frozen=True)
class MutationExpectation:
    expected_detections: list[str]
    forbidden_detections: list[str]


@dataclass(frozen=True)
class MutationDefinition:
    id: str
    description: str
    mutation_class: str
    category: str
    fixture: Path
    config: Path
    action: dict[str, Any]
    expectation: MutationExpectation


@dataclass(frozen=True)
class MutationCatalog:
    path: Path
    schema: str
    schema_version: int
    mutations: list[MutationDefinition]


@dataclass(frozen=True)
class MutationResult:
    id: str
    description: str
    mutation_class: str
    category: str
    passed: bool
    expected_detections: list[str]
    observed_detections: list[str]
    missed_detections: list[str]
    forbidden_detections: list[str]
    unexpected_detections: list[str]
    modified_files: list[str]
    evidence: dict[str, list[str]]
    check_results: list[CheckResult]
    command_events: list[CommandEvent]
    test_result: Optional[CommandResult]
    diff_summary: Optional[DiffSummary]
    score: int
    result: str
    duration_seconds: float
    warnings: list[str]
    runtime_error: Optional[str] = None


@dataclass(frozen=True)
class CheckDetectionSummary:
    check: str
    opportunities: int
    expected_detections: int
    observed_detections: int
    misses: int
    unexpected_detections: int


@dataclass(frozen=True)
class MutationAuditResult:
    audit_id: str
    schema: str
    schema_version: int
    created_at: str
    catalog_path: Path
    catalog_sha256: str
    catalog_schema: str
    catalog_schema_version: int
    strict: bool
    selected_mutation_ids: list[str]
    total_mutations: int
    safe_mutations: int
    unsafe_mutations: int
    expected_detections: int
    observed_expected_detections: int
    missed_detections: int
    forbidden_detections: int
    unexpected_detections: int
    safe_mutations_with_failed_checks: int
    controlled_mutation_detection_rate: float
    safe_fixture_pass_rate: float
    passed_mutations: int
    failed_mutations: int
    runtime_failures: int
    per_check: list[CheckDetectionSummary]
    per_category: dict[str, dict[str, object]]
    mutations: list[MutationResult]
    duration_seconds: float
    environment: dict[str, object]
    limitations: list[str]
    json_report_path: Path
    markdown_report_path: Path

    @property
    def has_failures(self) -> bool:
        return self.failed_mutations > 0


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"Mutation catalog field '{field}' must be a mapping.")
    return value


def _reject_unknown(
    mapping: dict[str, Any],
    allowed: set[str],
    field: str,
) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ValueError(
            f"Mutation catalog field '{field}' has unknown fields: "
            f"{', '.join(unknown)}."
        )


def _required_string(mapping: dict[str, Any], key: str, field: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"Mutation catalog field '{field}.{key}' must be a non-empty string."
        )
    return value


def _string_list(mapping: dict[str, Any], key: str, field: str) -> list[str]:
    value = mapping.get(key, [])
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ValueError(
            f"Mutation catalog field '{field}.{key}' must be a list of "
            "non-empty strings."
        )
    if len(value) != len(set(value)):
        raise ValueError(
            f"Mutation catalog field '{field}.{key}' must not contain duplicates."
        )
    return value


def _positive_int(mapping: dict[str, Any], key: str, field: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(
            f"Mutation catalog field '{field}.{key}' must be a positive integer."
        )
    return value


def _relative_action_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"Mutation catalog field '{field}' must be a non-empty relative path."
        )
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(
            f"Mutation catalog field '{field}' must stay within the workspace."
        )
    if normalized.startswith("/") or normalized in {"", "."}:
        raise ValueError(
            f"Mutation catalog field '{field}' must be a non-empty relative path."
        )
    return path.as_posix()


def _validate_action(value: Any, field: str, *, nested: bool = False) -> dict[str, Any]:
    action = _mapping(value, field)
    action_type = _required_string(action, "type", field)
    if action_type not in ACTION_TYPES:
        valid = ", ".join(sorted(ACTION_TYPES))
        raise ValueError(
            f"Mutation catalog field '{field}.type' must be one of: {valid}."
        )
    if action_type == "composite":
        if nested:
            raise ValueError("Nested composite mutation actions are not supported.")
        _reject_unknown(action, {"type", "actions"}, field)
        raw_actions = action.get("actions")
        if not isinstance(raw_actions, list) or not raw_actions:
            raise ValueError(
                f"Mutation catalog field '{field}.actions' must be a non-empty list."
            )
        return {
            "type": action_type,
            "actions": [
                _validate_action(item, f"{field}.actions[{index}]", nested=True)
                for index, item in enumerate(raw_actions)
            ],
        }
    if action_type == "record_event":
        _reject_unknown(action, {"type", "event"}, field)
        event = _required_string(action, "event", field)
        if event not in EVENT_PRESETS:
            valid = ", ".join(sorted(EVENT_PRESETS))
            raise ValueError(
                f"Mutation catalog field '{field}.event' must be one of: {valid}."
            )
        return {"type": action_type, "event": event}

    common = {"type", "path"}
    if action_type == "write_file":
        _reject_unknown(action, common | {"content"}, field)
        content = _required_string(action, "content", field)
        return {
            "type": action_type,
            "path": _relative_action_path(action.get("path"), f"{field}.path"),
            "content": content,
        }
    if action_type == "replace_text":
        _reject_unknown(action, common | {"old", "new"}, field)
        old = _required_string(action, "old", field)
        new = _required_string(action, "new", field)
        if old == new:
            raise ValueError(
                f"Mutation catalog field '{field}' old and new text must differ."
            )
        return {
            "type": action_type,
            "path": _relative_action_path(action.get("path"), f"{field}.path"),
            "old": old,
            "new": new,
        }
    if action_type == "append_lines":
        _reject_unknown(action, common | {"count", "prefix"}, field)
        prefix = _required_string(action, "prefix", field)
        count = _positive_int(action, "count", field)
        if count > 10000:
            raise ValueError(
                f"Mutation catalog field '{field}.count' must be at most 10000."
            )
        return {
            "type": action_type,
            "path": _relative_action_path(action.get("path"), f"{field}.path"),
            "count": count,
            "prefix": prefix,
        }
    if action_type in {"delete_path", "write_through_symlink"}:
        allowed = common | ({"content"} if action_type == "write_through_symlink" else set())
        _reject_unknown(action, allowed, field)
        normalized = {
            "type": action_type,
            "path": _relative_action_path(action.get("path"), f"{field}.path"),
        }
        if action_type == "write_through_symlink":
            normalized["content"] = _required_string(action, "content", field)
        return normalized
    raise AssertionError(f"Unhandled mutation action: {action_type}")


def _expectation(value: Any, field: str) -> MutationExpectation:
    mapping = _mapping(value, field)
    _reject_unknown(
        mapping,
        {"expected_detections", "forbidden_detections"},
        field,
    )
    expected = _string_list(mapping, "expected_detections", field)
    forbidden = _string_list(mapping, "forbidden_detections", field)
    unknown = sorted((set(expected) | set(forbidden)) - set(CHECK_NAMES))
    if unknown:
        raise ValueError(
            f"Mutation catalog field '{field}' references unknown checks: "
            f"{', '.join(unknown)}."
        )
    overlap = sorted(set(expected) & set(forbidden))
    if overlap:
        raise ValueError(
            f"Mutation catalog field '{field}' checks cannot be both expected "
            f"and forbidden: {', '.join(overlap)}."
        )
    return MutationExpectation(
        expected_detections=expected,
        forbidden_detections=forbidden,
    )


def load_mutation_catalog(path: Path = DEFAULT_CATALOG_PATH) -> MutationCatalog:
    catalog_path = path.expanduser()
    with catalog_path.open("r", encoding="utf-8") as file:
        data = yaml.load(file, Loader=_StrictSafeLoader) or {}
    mapping = _mapping(data, "catalog")
    _reject_unknown(
        mapping,
        {"schema", "schema_version", "mutations"},
        "catalog",
    )
    schema = _required_string(mapping, "schema", "catalog")
    if schema != CATALOG_SCHEMA:
        raise ValueError(f"Mutation catalog schema must be '{CATALOG_SCHEMA}'.")
    schema_version = mapping.get("schema_version")
    if schema_version != CATALOG_SCHEMA_VERSION:
        raise ValueError(
            f"Mutation catalog schema_version must be {CATALOG_SCHEMA_VERSION}."
        )
    raw_mutations = mapping.get("mutations")
    if not isinstance(raw_mutations, list) or not raw_mutations:
        raise ValueError("Mutation catalog field 'mutations' must be a non-empty list.")

    mutations: list[MutationDefinition] = []
    seen_ids: set[str] = set()
    for index, raw_mutation in enumerate(raw_mutations):
        field = f"catalog.mutations[{index}]"
        mutation = _mapping(raw_mutation, field)
        _reject_unknown(
            mutation,
            {
                "id",
                "description",
                "class",
                "category",
                "fixture",
                "config",
                "action",
                "expectation",
            },
            field,
        )
        mutation_id = _required_string(mutation, "id", field)
        if mutation_id in seen_ids:
            raise ValueError(f"Duplicate mutation id: {mutation_id}")
        seen_ids.add(mutation_id)
        mutation_class = _required_string(mutation, "class", field)
        if mutation_class not in MUTATION_CLASSES:
            raise ValueError(
                f"Mutation catalog field '{field}.class' must be safe or unsafe."
            )
        fixture_value = _required_string(mutation, "fixture", field)
        config_value = _required_string(mutation, "config", field)
        fixture = resolve_project_reference(fixture_value, catalog_path).resolve()
        config_path = resolve_project_reference(config_value, catalog_path).resolve()
        if not fixture.is_dir():
            raise ValueError(f"Mutation fixture does not exist: {fixture_value}")
        if not config_path.is_file():
            raise ValueError(f"Mutation config does not exist: {config_value}")
        config = load_config(config_path)
        if config.sandbox.type != "local":
            raise ValueError(
                f"Mutation config must use sandbox.type local: {config_value}"
            )
        if config.repo_template is None or config.repo_template.resolve() != fixture:
            raise ValueError(
                f"Mutation config repo_template does not match fixture: {config_value}"
            )
        mutations.append(
            MutationDefinition(
                id=mutation_id,
                description=_required_string(mutation, "description", field),
                mutation_class=mutation_class,
                category=_required_string(mutation, "category", field),
                fixture=fixture,
                config=config_path,
                action=_validate_action(mutation.get("action"), f"{field}.action"),
                expectation=_expectation(
                    mutation.get("expectation"),
                    f"{field}.expectation",
                ),
            )
        )
    return MutationCatalog(
        path=catalog_path.resolve(),
        schema=schema,
        schema_version=schema_version,
        mutations=mutations,
    )


def _workspace_path(repo_dir: Path, relative: str) -> Path:
    candidate = repo_dir / relative
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(repo_dir.resolve())
    except ValueError as error:
        raise ValueError(
            f"Mutation action path escapes isolated workspace: {relative}"
        ) from error
    return candidate


def _has_symlink_component(repo_dir: Path, relative: str) -> bool:
    current = repo_dir
    for part in PurePosixPath(relative).parts[:-1]:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _apply_action(
    action: dict[str, Any],
    repo_dir: Path,
    command_tracker: CommandTracker,
) -> None:
    action_type = action["type"]
    if action_type == "composite":
        for child in action["actions"]:
            _apply_action(child, repo_dir, command_tracker)
        return
    if action_type == "record_event":
        if action["event"] == "unsafe_rm":
            command_tracker.record_blocked_or_simulated(
                command=["rm", "-rf", "important_data"],
                command_text="rm -rf important_data",
                cwd=repo_dir,
                blocked=True,
                reason="Controlled mutation unsafe command event",
            )
            return
        completed = subprocess.run(
            ["git", "status", "--short"],
            cwd=repo_dir,
            check=False,
            capture_output=True,
            text=True,
        )
        command_tracker.record_executed(
            command=["git", "status", "--short"],
            command_text="git status --short",
            cwd=repo_dir,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            duration_seconds=0.0,
        )
        return

    relative = action["path"]
    path = _workspace_path(repo_dir, relative)
    if action_type == "write_file":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(action["content"], encoding="utf-8")
        return
    if action_type == "replace_text":
        if not path.is_file():
            raise ValueError(f"Mutation replace target does not exist: {relative}")
        content = path.read_text(encoding="utf-8")
        if action["old"] not in content:
            raise ValueError(
                f"Mutation replace text was not found in target: {relative}"
            )
        path.write_text(
            content.replace(action["old"], action["new"], 1),
            encoding="utf-8",
        )
        return
    if action_type == "append_lines":
        path.parent.mkdir(parents=True, exist_ok=True)
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        if existing and not existing.endswith("\n"):
            existing += "\n"
        generated = "".join(
            f"# {action['prefix']} {index:04d}\n"
            for index in range(1, action["count"] + 1)
        )
        path.write_text(existing + generated, encoding="utf-8")
        return
    if action_type == "delete_path":
        if not path.is_file() and not path.is_symlink():
            raise ValueError(f"Mutation delete target does not exist: {relative}")
        path.unlink()
        return
    if action_type == "write_through_symlink":
        if not _has_symlink_component(repo_dir, relative):
            raise ValueError(
                f"Mutation symlink write path has no symlink component: {relative}"
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(action["content"], encoding="utf-8")
        return
    raise AssertionError(f"Unhandled mutation action: {action_type}")


def _git(repo_dir: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        text=True,
    )


def _prepare_workspace(mutation: MutationDefinition, root: Path) -> Path:
    repo_dir = root / mutation.id
    shutil.copytree(mutation.fixture, repo_dir, symlinks=True)
    _git(repo_dir, "init")
    _git(repo_dir, "add", ".")
    _git(
        repo_dir,
        "-c",
        "user.email=agentguard@example.local",
        "-c",
        "user.name=AgentGuard",
        "commit",
        "-m",
        "Initial mutation fixture state",
    )
    return repo_dir


def _evaluate_mutation(
    mutation: MutationDefinition,
    repo_dir: Path,
    config: AgentGuardConfig,
    *,
    strict: bool,
) -> MutationResult:
    started = time.perf_counter()
    command_tracker = CommandTracker()
    _apply_action(mutation.action, repo_dir, command_tracker)
    test_result = TestRunner(
        command_tracker,
        timeout_seconds=config.command_timeout_seconds,
        max_output_bytes=config.max_output_bytes,
    ).run(repo_dir, config.test_command)
    diff_summary = collect_diff(repo_dir)
    check_results = [
        check.run(config, test_result, diff_summary, command_tracker.events)
        for check in default_checks()
    ]
    score = score_checks(check_results)
    observed = [check.name for check in check_results if not check.passed]
    expected = mutation.expectation.expected_detections
    forbidden = mutation.expectation.forbidden_detections
    missed = [check for check in expected if check not in observed]
    forbidden_observed = [check for check in forbidden if check in observed]
    unexpected = [check for check in observed if check not in expected]
    additional = [check for check in unexpected if check not in forbidden]
    warnings = [
        f"Unexpected failed check observed: {check}" for check in additional
    ]
    passed = not missed and not forbidden_observed and not (strict and additional)
    return MutationResult(
        id=mutation.id,
        description=mutation.description,
        mutation_class=mutation.mutation_class,
        category=mutation.category,
        passed=passed,
        expected_detections=list(expected),
        observed_detections=observed,
        missed_detections=missed,
        forbidden_detections=forbidden_observed,
        unexpected_detections=unexpected,
        modified_files=sorted(diff_summary.changed_files),
        evidence={
            check.name: list(check.evidence)
            for check in check_results
            if not check.passed
        },
        check_results=check_results,
        command_events=command_tracker.events,
        test_result=test_result,
        diff_summary=diff_summary,
        score=score.score,
        result=score.result,
        duration_seconds=round(time.perf_counter() - started, 6),
        warnings=warnings,
    )


def _runtime_failure(
    mutation: MutationDefinition,
    error: Exception,
    duration_seconds: float,
) -> MutationResult:
    message = f"{type(error).__name__}: {error}"
    return MutationResult(
        id=mutation.id,
        description=mutation.description,
        mutation_class=mutation.mutation_class,
        category=mutation.category,
        passed=False,
        expected_detections=list(
            mutation.expectation.expected_detections
        ),
        observed_detections=[],
        missed_detections=list(
            mutation.expectation.expected_detections
        ),
        forbidden_detections=[],
        unexpected_detections=[],
        modified_files=[],
        evidence={},
        check_results=[],
        command_events=[],
        test_result=None,
        diff_summary=None,
        score=0,
        result="FAIL",
        duration_seconds=round(duration_seconds, 6),
        warnings=[],
        runtime_error=message,
    )


def _rate(numerator: int, denominator: int) -> float:
    return round((numerator / denominator) * 100.0, 2) if denominator else 100.0


def check_detection_summaries(
    results: list[MutationResult],
) -> list[CheckDetectionSummary]:
    summaries = []
    for check in CHECK_NAMES:
        expected = sum(check in result.expected_detections for result in results)
        observed = sum(check in result.observed_detections for result in results)
        misses = sum(check in result.missed_detections for result in results)
        unexpected = sum(
            check in result.observed_detections
            and check not in result.expected_detections
            for result in results
        )
        summaries.append(
            CheckDetectionSummary(
                check=check,
                opportunities=len(results),
                expected_detections=expected,
                observed_detections=observed,
                misses=misses,
                unexpected_detections=unexpected,
            )
        )
    return summaries


def _metrics(results: list[MutationResult]) -> dict[str, object]:
    expected = sum(len(result.expected_detections) for result in results)
    observed_expected = sum(
        len(set(result.expected_detections) & set(result.observed_detections))
        for result in results
    )
    safe = [result for result in results if result.mutation_class == "safe"]
    safe_passes = sum(not result.observed_detections for result in safe)
    return {
        "total_mutations": len(results),
        "safe_mutations": len(safe),
        "unsafe_mutations": sum(
            result.mutation_class == "unsafe" for result in results
        ),
        "expected_detections": expected,
        "observed_expected_detections": observed_expected,
        "missed_detections": sum(
            len(result.missed_detections) for result in results
        ),
        "forbidden_detections": sum(
            len(result.forbidden_detections) for result in results
        ),
        "unexpected_detections": sum(
            len(result.unexpected_detections) for result in results
        ),
        "safe_mutations_with_failed_checks": sum(
            bool(result.observed_detections) for result in safe
        ),
        "controlled_mutation_detection_rate": _rate(
            observed_expected,
            expected,
        ),
        "safe_fixture_pass_rate": _rate(safe_passes, len(safe)),
        "passed_mutations": sum(result.passed for result in results),
        "failed_mutations": sum(not result.passed for result in results),
        "runtime_failures": sum(
            result.runtime_error is not None for result in results
        ),
    }


def _category_metrics(
    results: list[MutationResult],
) -> dict[str, dict[str, object]]:
    categories: dict[str, list[MutationResult]] = {}
    for result in results:
        categories.setdefault(result.category, []).append(result)
    return {
        category: _metrics(category_results)
        for category, category_results in categories.items()
    }


def _audit_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    return f"mutation-audit-{timestamp}-{uuid4().hex[:8]}"


def _json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _write_reports(result: MutationAuditResult) -> None:
    result.json_report_path.parent.mkdir(parents=True, exist_ok=True)
    with result.json_report_path.open("w", encoding="utf-8") as file:
        json.dump(
            asdict(result),
            file,
            default=_json_default,
            indent=2,
            sort_keys=True,
        )
        file.write("\n")

    lines = [
        "# AgentGuard Policy Mutation Audit",
        "",
        "## Summary",
        "",
        f"- Mutations: {result.total_mutations}",
        f"- Safe mutations: {result.safe_mutations}",
        f"- Unsafe mutations: {result.unsafe_mutations}",
        f"- Expected detections: {result.expected_detections}",
        f"- Observed expected detections: "
        f"{result.observed_expected_detections}",
        f"- Controlled mutation detection rate: "
        f"{result.controlled_mutation_detection_rate:.2f}%",
        f"- Safe-fixture pass rate: {result.safe_fixture_pass_rate:.2f}%",
        f"- Safe mutations with failed checks: "
        f"{result.safe_mutations_with_failed_checks}",
        f"- Missed detections: {result.missed_detections}",
        f"- Forbidden detections: {result.forbidden_detections}",
        f"- Unexpected detections: {result.unexpected_detections}",
        f"- Runtime failures: {result.runtime_failures}",
        f"- Strict mode: {result.strict}",
        "",
        "## Audit Metadata",
        "",
        f"- Catalog: {result.catalog_path}",
        f"- Catalog schema: {result.catalog_schema} "
        f"v{result.catalog_schema_version}",
        f"- Catalog SHA-256: {result.catalog_sha256}",
        f"- AgentGuard version: {result.environment['agentguard_version']}",
        f"- AgentGuard commit: "
        f"{result.environment['agentguard_git_commit'] or '-'}",
        f"- Python: {result.environment['python_version']}",
        f"- Operating system: {result.environment['operating_system']}",
        f"- Architecture: {result.environment['architecture']}",
        f"- Duration: {result.duration_seconds:.6f}s",
        "",
        "## Per-Check Detection",
        "",
        "| Check | Opportunities | Expected | Observed | Misses | Unexpected |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for check in result.per_check:
        lines.append(
            f"| {check.check} | {check.opportunities} | "
            f"{check.expected_detections} | {check.observed_detections} | "
            f"{check.misses} | {check.unexpected_detections} |"
        )
    lines.extend(
        [
            "",
            "## Per-Category Results",
            "",
            "| Category | Mutations | Expected | Observed Expected | Missed | "
            "Unexpected | Detection Rate | Safe Pass Rate |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for category, metrics in result.per_category.items():
        lines.append(
            f"| {category} | {metrics['total_mutations']} | "
            f"{metrics['expected_detections']} | "
            f"{metrics['observed_expected_detections']} | "
            f"{metrics['missed_detections']} | "
            f"{metrics['unexpected_detections']} | "
            f"{float(metrics['controlled_mutation_detection_rate']):.2f}% | "
            f"{float(metrics['safe_fixture_pass_rate']):.2f}% |"
        )
    lines.extend(
        [
            "",
            "## Mutation Results",
            "",
            "| Mutation | Class | Category | Status | Expected | Observed | "
            "Missed | Forbidden | Unexpected |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
    )
    for mutation in result.mutations:
        status = "PASS" if mutation.passed else "FAIL"
        values = [
            mutation.id,
            mutation.mutation_class,
            mutation.category,
            status,
            ", ".join(mutation.expected_detections) or "-",
            ", ".join(mutation.observed_detections) or "-",
            ", ".join(mutation.missed_detections) or "-",
            ", ".join(mutation.forbidden_detections) or "-",
            ", ".join(mutation.unexpected_detections) or "-",
        ]
        lines.append("| " + " | ".join(values) + " |")
    lines.extend(["", "## Evidence", ""])
    for mutation in result.mutations:
        lines.append(f"### {mutation.id}")
        lines.append("")
        lines.append(
            f"- Modified files: {', '.join(mutation.modified_files) or '-'}"
        )
        lines.append(f"- Duration: {mutation.duration_seconds:.6f}s")
        if mutation.runtime_error:
            lines.append(f"- Runtime error: {mutation.runtime_error}")
        for check, evidence in mutation.evidence.items():
            lines.append(f"- {check}: {', '.join(evidence) or '(no evidence)'}")
        if not mutation.evidence and not mutation.runtime_error:
            lines.append("- Failed-check evidence: None")
        lines.append("")
    lines.extend(["## Limitations", ""])
    lines.extend(f"- {limitation}" for limitation in result.limitations)
    lines.append("")
    result.markdown_report_path.write_text("\n".join(lines), encoding="utf-8")


def _select_mutations(
    catalog: MutationCatalog,
    mutation_ids: list[str],
    category: Optional[str],
) -> list[MutationDefinition]:
    known = {mutation.id for mutation in catalog.mutations}
    missing = [mutation_id for mutation_id in mutation_ids if mutation_id not in known]
    if missing:
        raise ValueError(f"Unknown mutation ids: {', '.join(missing)}")
    selected = [
        mutation
        for mutation in catalog.mutations
        if (not mutation_ids or mutation.id in mutation_ids)
        and (category is None or mutation.category == category)
    ]
    if not selected:
        raise ValueError("Mutation filters matched no catalog entries.")
    return selected


def run_mutation_audit(
    catalog_path: Path = DEFAULT_CATALOG_PATH,
    *,
    mutation_ids: Optional[list[str]] = None,
    category: Optional[str] = None,
    output_dir: Optional[Path] = None,
    strict: bool = False,
) -> MutationAuditResult:
    catalog = load_mutation_catalog(catalog_path)
    normalized_ids = normalize_registry_values(mutation_ids)
    selected = _select_mutations(catalog, normalized_ids, category)
    started = time.perf_counter()
    audit_id = _audit_id()
    audit_dir = (output_dir or DEFAULT_OUTPUT_DIR) / audit_id
    workspace_root = audit_dir / "workspaces"
    results: list[MutationResult] = []
    for mutation in selected:
        mutation_started = time.perf_counter()
        try:
            repo_dir = _prepare_workspace(mutation, workspace_root)
            config = load_config(mutation.config)
            results.append(
                _evaluate_mutation(
                    mutation,
                    repo_dir,
                    config,
                    strict=strict,
                )
            )
        except Exception as error:
            results.append(
                _runtime_failure(
                    mutation,
                    error,
                    time.perf_counter() - mutation_started,
                )
            )
    shutil.rmtree(workspace_root, ignore_errors=True)

    metrics = _metrics(results)
    identity = agentguard_identity()
    host = host_identity(docker_relevant=False)
    result = MutationAuditResult(
        audit_id=audit_id,
        schema=AUDIT_SCHEMA,
        schema_version=AUDIT_SCHEMA_VERSION,
        created_at=datetime.now(timezone.utc).isoformat(),
        catalog_path=catalog.path,
        catalog_sha256=sha256_file(catalog.path),
        catalog_schema=catalog.schema,
        catalog_schema_version=catalog.schema_version,
        strict=strict,
        selected_mutation_ids=[mutation.id for mutation in selected],
        total_mutations=int(metrics["total_mutations"]),
        safe_mutations=int(metrics["safe_mutations"]),
        unsafe_mutations=int(metrics["unsafe_mutations"]),
        expected_detections=int(metrics["expected_detections"]),
        observed_expected_detections=int(
            metrics["observed_expected_detections"]
        ),
        missed_detections=int(metrics["missed_detections"]),
        forbidden_detections=int(metrics["forbidden_detections"]),
        unexpected_detections=int(metrics["unexpected_detections"]),
        safe_mutations_with_failed_checks=int(
            metrics["safe_mutations_with_failed_checks"]
        ),
        controlled_mutation_detection_rate=float(
            metrics["controlled_mutation_detection_rate"]
        ),
        safe_fixture_pass_rate=float(metrics["safe_fixture_pass_rate"]),
        passed_mutations=int(metrics["passed_mutations"]),
        failed_mutations=int(metrics["failed_mutations"]),
        runtime_failures=int(metrics["runtime_failures"]),
        per_check=check_detection_summaries(results),
        per_category=_category_metrics(results),
        mutations=results,
        duration_seconds=round(time.perf_counter() - started, 6),
        environment={
            "agentguard_version": identity.version,
            "agentguard_git_commit": identity.git_commit,
            "agentguard_dirty_worktree": identity.dirty_worktree,
            "python_version": host.python_version,
            "operating_system": host.operating_system,
            "architecture": host.architecture,
        },
        limitations=[
            "Controlled synthetic mutations do not estimate production violation prevalence.",
            "Controlled mutation detection rate is not a real-world false-negative rate.",
            "Safe-fixture pass rate is not a real-world false-positive rate.",
            "The catalog covers deterministic repository and command-event evidence only.",
            "Results depend on the selected fixtures, policies, and check configuration.",
        ],
        json_report_path=audit_dir / "mutations.json",
        markdown_report_path=audit_dir / "mutations.md",
    )
    _write_reports(result)
    return result
