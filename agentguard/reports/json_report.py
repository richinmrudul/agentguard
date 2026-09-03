from pathlib import Path
from typing import Any

from agentguard.core.result import BenchmarkResult
from agentguard.io import atomic_write_json
from agentguard.provenance.artifact_paths import (
    artifact_roots,
    portable_artifact_value,
)


def _json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def write_json_report(result: BenchmarkResult, reports_dir: Path) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "report.json"
    roots = artifact_roots(
        repository_root=result.repo_dir,
        run_root=result.run_dir,
        config_path=result.config_path,
    )
    data = portable_artifact_value(result, roots)
    if isinstance(data.get("benchmark"), dict):
        data["benchmark"] = {
            key: value
            for key, value in data["benchmark"].items()
            if value not in (None, [])
        }
    if result.sandbox is not None and result.sandbox.type == "local":
        data["sandbox"] = {
            "type": result.sandbox.type,
            "timeout_seconds": result.sandbox.timeout_seconds,
            "max_output_bytes": result.sandbox.max_output_bytes,
        }
    elif isinstance(data.get("sandbox"), dict):
        data["sandbox"] = {
            key: value for key, value in data["sandbox"].items() if value is not None
        }
    data["command_log_path"] = portable_artifact_value(
        result.report_paths.command_log,
        roots,
    )
    data["manifest_path"] = portable_artifact_value(result.report_paths.manifest, roots)
    data["trace_path"] = portable_artifact_value(result.report_paths.trace, roots)
    data["guard_incident_path"] = portable_artifact_value(
        result.report_paths.guard_incident_json,
        roots,
    )
    data["guard_incident_markdown_path"] = (
        portable_artifact_value(result.report_paths.guard_incident_markdown, roots)
    )
    data["provenance"] = result.provenance_summary
    data["evidence"] = [
        evidence for check in result.check_results for evidence in check.evidence
    ]
    atomic_write_json(report_path, data, default=_json_default)
    return report_path
