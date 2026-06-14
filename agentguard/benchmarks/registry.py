from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import yaml

from agentguard.config.yaml import load_yaml
from agentguard.config.schema import VALID_BENCHMARK_DIFFICULTIES
from agentguard.io import atomic_write_text


DEFAULT_REGISTRY_PATH = Path("examples/benchmarks/registry.yaml")


class _IndentedSafeDumper(yaml.SafeDumper):
    def increase_indent(self, flow: bool = False, indentless: bool = False) -> Any:
        return super().increase_indent(flow, False)


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
    contract: Path


@dataclass(frozen=True)
class BenchmarkRegistry:
    path: Path
    benchmarks: list[BenchmarkRegistryEntry]


def normalize_registry_values(raw_values: Optional[list[str]]) -> list[str]:
    if raw_values is None:
        return []
    values: list[str] = []
    for raw_value in raw_values:
        for value in raw_value.split(","):
            normalized = value.strip()
            if normalized:
                values.append(normalized)
    return values


def _required_string(
    entry: dict[str, Any],
    key: str,
    index: int,
) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Benchmark registry entry {index} field '{key}' is required.")
    return value


def resolve_project_reference(value: str, anchor_path: Path) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute() or path.exists():
        return path
    for parent in anchor_path.expanduser().resolve().parents:
        candidate = parent / path
        if candidate.exists():
            return candidate
    return path


def _load_entry(
    raw_entry: Any,
    index: int,
    registry_path: Path,
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
        path = resolve_project_reference(config_path, registry_path)
        if not path.exists():
            raise ValueError(
                f"Benchmark registry entry {index} config '{label}' "
                f"path does not exist: {config_path}"
            )
        configs[label] = path

    contract_value = raw_entry.get("contract")
    if not isinstance(contract_value, str) or not contract_value:
        raise ValueError(
            f"Benchmark registry entry {index} field 'contract' "
            "must be a non-empty string path."
        )
    contract = resolve_project_reference(contract_value, registry_path)
    if not contract.exists():
        raise ValueError(
            f"Benchmark registry entry {index} contract path does not exist: "
            f"{contract_value}"
        )

    return BenchmarkRegistryEntry(
        id=benchmark_id,
        version=version,
        name=name,
        category=category,
        difficulty=difficulty,
        description=description,
        tags=tags,
        configs=configs,
        contract=contract,
    )


def load_benchmark_registry(path: Path = DEFAULT_REGISTRY_PATH) -> BenchmarkRegistry:
    registry_path = path.expanduser()
    with registry_path.open("r", encoding="utf-8") as file:
        data = load_yaml(file) or {}

    if not isinstance(data, dict):
        raise ValueError("Benchmark registry must be a YAML mapping.")

    raw_benchmarks = data.get("benchmarks")
    if not isinstance(raw_benchmarks, list):
        raise ValueError("Benchmark registry field 'benchmarks' must be a list.")

    benchmarks = [
        _load_entry(raw_entry, index, registry_path)
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


def _matches_generation_filters(
    benchmark: BenchmarkRegistryEntry,
    category: Optional[str],
    difficulty: Optional[str],
    tags: list[str],
) -> bool:
    if category is not None and benchmark.category != category:
        return False
    if difficulty is not None and benchmark.difficulty != difficulty:
        return False
    if tags and not set(tags).issubset(set(benchmark.tags)):
        return False
    return True


def generate_suite_data(
    registry: BenchmarkRegistry,
    suite_id: str,
    description: str,
    include: Optional[list[str]] = None,
    category: Optional[str] = None,
    difficulty: Optional[str] = None,
    tags: Optional[list[str]] = None,
) -> dict[str, Any]:
    normalized_include = normalize_registry_values(include)
    normalized_tags = normalize_registry_values(tags)
    normalized_category = category.strip() if category is not None else None
    normalized_difficulty = difficulty.strip() if difficulty is not None else None
    if normalized_category == "":
        raise ValueError("Registry suite filter 'category' must be a non-empty string.")
    if normalized_difficulty == "":
        raise ValueError("Registry suite filter 'difficulty' must be a non-empty string.")

    runs: list[dict[str, str]] = []
    for benchmark in registry.benchmarks:
        if not _matches_generation_filters(
            benchmark,
            normalized_category,
            normalized_difficulty,
            normalized_tags,
        ):
            continue

        config_keys = normalized_include or list(benchmark.configs.keys())
        for config_key in config_keys:
            config_path = benchmark.configs.get(config_key)
            if config_path is None:
                continue
            runs.append({"config": str(config_path), "agent": "custom-command"})

    if not runs:
        raise ValueError("registry suite generation produced no runs.")

    return {
        "suite_id": suite_id,
        "description": description,
        "runs": runs,
    }


def write_generated_suite(
    suite_data: dict[str, Any],
    output_path: Path,
    force: bool = False,
) -> Path:
    path = output_path.expanduser()
    if path.exists() and not force:
        raise ValueError(f"output already exists: {path}")
    content = yaml.dump(
        suite_data,
        Dumper=_IndentedSafeDumper,
        sort_keys=False,
        default_flow_style=False,
    )
    atomic_write_text(path, content)
    return path
