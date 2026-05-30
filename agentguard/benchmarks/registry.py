from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import yaml

from agentguard.config.schema import VALID_BENCHMARK_DIFFICULTIES


DEFAULT_REGISTRY_PATH = Path("examples/benchmarks/registry.yaml")


@dataclass(frozen=True)
class BenchmarkRegistryEntry:
    id: str
    version: int
    name: str
    category: str
    difficulty: str
    description: str
    tags: list[str]
    configs: dict[str, Path]


@dataclass(frozen=True)
class BenchmarkRegistry:
    path: Path
    benchmarks: list[BenchmarkRegistryEntry]


def _required_string(
    entry: dict[str, Any],
    key: str,
    index: int,
) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Benchmark registry entry {index} field '{key}' is required.")
    return value


def _load_entry(
    raw_entry: Any,
    index: int,
) -> BenchmarkRegistryEntry:
    if not isinstance(raw_entry, dict):
        raise ValueError(f"Benchmark registry entry {index} must be a mapping.")

    benchmark_id = _required_string(raw_entry, "id", index)
    name = _required_string(raw_entry, "name", index)
    category = _required_string(raw_entry, "category", index)
    difficulty = _required_string(raw_entry, "difficulty", index)
    if difficulty not in VALID_BENCHMARK_DIFFICULTIES:
        valid = ", ".join(sorted(VALID_BENCHMARK_DIFFICULTIES))
        raise ValueError(
            f"Benchmark registry entry {index} field 'difficulty' "
            f"must be one of: {valid}."
        )

    version = raw_entry.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version <= 0:
        raise ValueError(
            f"Benchmark registry entry {index} field 'version' "
            "must be a positive integer."
        )

    description = _required_string(raw_entry, "description", index)

    tags = raw_entry.get("tags")
    if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
        raise ValueError(
            f"Benchmark registry entry {index} field 'tags' "
            "must be a list of strings."
        )

    raw_configs = raw_entry.get("configs")
    if not isinstance(raw_configs, dict) or not raw_configs:
        raise ValueError(
            f"Benchmark registry entry {index} field 'configs' "
            "must be a non-empty mapping."
        )

    configs: dict[str, Path] = {}
    for label, config_path in raw_configs.items():
        if not isinstance(label, str) or not label:
            raise ValueError(
                f"Benchmark registry entry {index} field 'configs' "
                "must use non-empty string keys."
            )
        if not isinstance(config_path, str) or not config_path:
            raise ValueError(
                f"Benchmark registry entry {index} config '{label}' "
                "must be a non-empty string path."
            )
        path = Path(config_path)
        if not path.exists():
            raise ValueError(
                f"Benchmark registry entry {index} config '{label}' "
                f"path does not exist: {config_path}"
            )
        configs[label] = path

    return BenchmarkRegistryEntry(
        id=benchmark_id,
        version=version,
        name=name,
        category=category,
        difficulty=difficulty,
        description=description,
        tags=tags,
        configs=configs,
    )


def load_benchmark_registry(path: Path = DEFAULT_REGISTRY_PATH) -> BenchmarkRegistry:
    registry_path = path.expanduser()
    with registry_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    if not isinstance(data, dict):
        raise ValueError("Benchmark registry must be a YAML mapping.")

    raw_benchmarks = data.get("benchmarks")
    if not isinstance(raw_benchmarks, list):
        raise ValueError("Benchmark registry field 'benchmarks' must be a list.")

    benchmarks = [
        _load_entry(raw_entry, index)
        for index, raw_entry in enumerate(raw_benchmarks)
    ]

    seen_ids: set[str] = set()
    for entry in benchmarks:
        if entry.id in seen_ids:
            raise ValueError(f"Duplicate benchmark id in registry: {entry.id}")
        seen_ids.add(entry.id)

    return BenchmarkRegistry(path=registry_path, benchmarks=benchmarks)


def find_benchmark(
    registry: BenchmarkRegistry,
    benchmark_id: str,
) -> Optional[BenchmarkRegistryEntry]:
    for benchmark in registry.benchmarks:
        if benchmark.id == benchmark_id:
            return benchmark
    return None
