#!/usr/bin/env python3
import argparse
import json
import platform
import statistics
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

import yaml

from agentguard import __version__
from agentguard.benchmarks.registry import load_benchmark_registry
from agentguard.core.orchestrator import run_benchmark
from agentguard.io import atomic_write_json
from agentguard.traces.replay import replay_trace


def _git_commit() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _local_config(
    source: Path,
    destination: Path,
    *,
    synthetic_symlink_adversary: bool,
) -> None:
    data = yaml.safe_load(source.read_text(encoding="utf-8"))
    data["sandbox"] = {
        "type": "local",
        "timeout_seconds": data.get("sandbox", {}).get(
            "timeout_seconds",
            60,
        ),
    }
    for key in ("agent_command", "test_command"):
        command = data.get(key)
        if isinstance(command, str) and command.startswith("python "):
            data[key] = f"{sys.executable} {command[len('python '):]}"
        elif (
            isinstance(command, list)
            and command
            and command[0] == "python"
        ):
            data[key] = [sys.executable, *command[1:]]
    if synthetic_symlink_adversary:
        data["agent_command"] = [
            sys.executable,
            "-c",
            (
                "from pathlib import Path; "
                "Path('secrets').mkdir(exist_ok=True); "
                "Path('secrets/agent.key').write_text('synthetic\\n')"
            ),
        ]
    destination.write_text(
        yaml.safe_dump(data, sort_keys=False),
        encoding="utf-8",
    )


def run_study(output: Path) -> dict[str, object]:
    registry = load_benchmark_registry()
    cases = []
    with tempfile.TemporaryDirectory(prefix="agentguard-replay-study-") as raw:
        root = Path(raw)
        for benchmark in registry.benchmarks:
            for scenario, config_path in benchmark.configs.items():
                local_config = root / f"{benchmark.id}-{scenario}.yaml"
                _local_config(
                    config_path,
                    local_config,
                    synthetic_symlink_adversary=(
                        benchmark.id == "symlink_path_traversal"
                        and scenario == "adversarial"
                    ),
                )
                result = run_benchmark(local_config, "agent-command")
                assert result.report_paths.trace is not None
                replay = replay_trace(
                    result.report_paths.trace,
                    output_dir=root / "replays" / benchmark.id / scenario,
                )
                cases.append(
                    {
                        "benchmark_family": benchmark.id,
                        "scenario": scenario,
                        "recorded_result": replay.recorded_result,
                        "replayable": replay.replayability.replayable,
                        "check_equivalence": all(
                            item.classification == "exact"
                            for item in replay.comparisons
                        ),
                        "score_equivalence": (
                            replay.recorded_score == replay.recomputed_score
                        ),
                        "result_equivalence": (
                            replay.recorded_result == replay.recomputed_result
                        ),
                        "equivalence": replay.equivalence,
                        "recorded_duration_seconds": (
                            replay.original_duration_seconds
                        ),
                        "replay_duration_seconds": replay.replay_duration_seconds,
                        "speedup_ratio": replay.speedup_ratio,
                    }
                )
    replayable = [case for case in cases if case["replayable"]]
    ratios = [
        case["speedup_ratio"]
        for case in replayable
        if case["speedup_ratio"] is not None
    ]
    summary = {
        "schema": "agentguard.trace-replay-equivalence",
        "schema_version": 1,
        "date": date.today().isoformat(),
        "agentguard_commit": _git_commit(),
        "source_state": "working tree containing deterministic trace replay",
        "environment": {
            "agentguard_version": __version__,
            "python_version": platform.python_version(),
            "operating_system": platform.system(),
            "architecture": platform.machine(),
        },
        "methodology": {
            "registry": "examples/benchmarks/registry.yaml",
            "benchmark_families": len(registry.benchmarks),
            "scenarios_per_family": ["safe", "adversarial"],
            "execution": (
                "Docker settings were replaced in temporary configs with the "
                "local agent-command adapter; replay then consumed only trace "
                "evidence and invoked no agent, test command, Docker, network, "
                "or benchmark workspace."
            ),
            "symlink_adversary": (
                "The adversarial symlink scenario used synthetic in-workspace "
                "forbidden-path evidence to avoid following a host-facing link."
            ),
        },
        "aggregates": {
            "traces_attempted": len(cases),
            "traces_replayable": len(replayable),
            "exact_check_equivalence_count": sum(
                bool(case["check_equivalence"]) for case in replayable
            ),
            "exact_score_equivalence_count": sum(
                bool(case["score_equivalence"]) for case in replayable
            ),
            "exact_final_result_equivalence_count": sum(
                bool(case["result_equivalence"]) for case in replayable
            ),
            "non_replayable_traces": len(cases) - len(replayable),
            "total_recorded_execution_duration_seconds": round(
                sum(
                    float(case["recorded_duration_seconds"] or 0.0)
                    for case in replayable
                ),
                6,
            ),
            "total_replay_duration_seconds": round(
                sum(
                    float(case["replay_duration_seconds"])
                    for case in replayable
                ),
                6,
            ),
            "median_measured_speedup_ratio": (
                round(statistics.median(ratios), 2) if ratios else None
            ),
        },
        "cases": cases,
        "limitations": [
            "This measures policy replay equivalence, not agent-behavior replay.",
            "Original execution timing is machine-specific.",
            "Local fixture execution is not a Docker containment claim.",
            "Synthetic symlink evidence does not exercise host path traversal.",
            "Exact equivalence applies only to captured, supported policy inputs.",
        ],
    }
    atomic_write_json(output, summary, sort_keys=False)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/results/trace-replay-equivalence.json"),
    )
    args = parser.parse_args()
    summary = run_study(args.output)
    print(json.dumps(summary["aggregates"], indent=2))


if __name__ == "__main__":
    main()
