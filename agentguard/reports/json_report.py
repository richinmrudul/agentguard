from dataclasses import asdict
from pathlib import Path
from typing import Any

from agentguard.core.result import BenchmarkResult
from agentguard.io import atomic_write_json


def _json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def write_json_report(result: BenchmarkResult, reports_dir: Path) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "report.json"
    data = asdict(result)
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
    data["command_log_path"] = result.report_paths.command_log
    data["manifest_path"] = result.report_paths.manifest
    data["trace_path"] = result.report_paths.trace
    data["provenance"] = result.provenance_summary
    data["evidence"] = [
        evidence for check in result.check_results for evidence in check.evidence
    ]
    atomic_write_json(report_path, data, default=_json_default)
    return report_path
