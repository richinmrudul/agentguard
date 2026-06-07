from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from agentguard.benchmarks.registry import (
    BenchmarkRegistry,
    BenchmarkRegistryEntry,
    resolve_project_reference,
)
from agentguard.config.loader import load_config


CONTRACT_SCHEMA = "agentguard.benchmark-contract"
CONTRACT_SCHEMA_VERSION = 1


class _StrictSafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"Duplicate YAML mapping key in contract: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


@dataclass(frozen=True)
class ScoreExpectation:
    min: int
    max: int


@dataclass(frozen=True)
class PatternExpectation:
    required: list[str]
    forbidden: list[str]


@dataclass(frozen=True)
class ModifiedPathExpectation:
    required: list[str]
    allowed: list[str]
    forbidden: list[str]


@dataclass(frozen=True)
class ContractExpectation:
    result: str
    functional_tests: str
    score: ScoreExpectation
    modified_paths: ModifiedPathExpectation
    failed_checks: PatternExpectation
    evidence_patterns: PatternExpectation


@dataclass(frozen=True)
class ContractVariant:
    name: str
    config: Path
    expected: ContractExpectation


@dataclass(frozen=True)
class BenchmarkContract:
    path: Path
    schema: str
    schema_version: int
    benchmark_id: str
    benchmark_version: int
    variants: list[ContractVariant]


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"Contract field '{field}' must be a mapping.")
    return value


def _reject_unknown(
    mapping: dict[str, Any],
    allowed: set[str],
    field: str,
) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ValueError(
            f"Contract field '{field}' has unknown fields: {', '.join(unknown)}."
        )


def _required_string(mapping: dict[str, Any], key: str, field: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Contract field '{field}.{key}' must be a non-empty string.")
    return value


def _string_list(mapping: dict[str, Any], key: str, field: str) -> list[str]:
    value = mapping.get(key, [])
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ValueError(
            f"Contract field '{field}.{key}' must be a list of non-empty strings."
        )
    return value


def _patterns(value: Any, field: str, *, allowed_key: bool = False):
    mapping = _mapping(value, field)
    allowed = {"required", "forbidden"}
    if allowed_key:
        allowed.add("allowed")
    _reject_unknown(mapping, allowed, field)
    required = _string_list(mapping, "required", field)
    forbidden = _string_list(mapping, "forbidden", field)
    overlap = sorted(set(required) & set(forbidden))
    if overlap:
        raise ValueError(
            f"Contract field '{field}' patterns cannot be both required and "
            f"forbidden: {', '.join(overlap)}."
        )
    if allowed_key:
        return ModifiedPathExpectation(
            required=required,
            allowed=_string_list(mapping, "allowed", field),
            forbidden=forbidden,
        )
    return PatternExpectation(required=required, forbidden=forbidden)


def _score(value: Any, field: str) -> ScoreExpectation:
    mapping = _mapping(value, field)
    _reject_unknown(mapping, {"min", "max"}, field)
    minimum = mapping.get("min")
    maximum = mapping.get("max")
    for key, number in (("min", minimum), ("max", maximum)):
        if (
            not isinstance(number, int)
            or isinstance(number, bool)
            or not 0 <= number <= 100
        ):
            raise ValueError(
                f"Contract field '{field}.{key}' must be an integer from 0 to 100."
            )
    if minimum > maximum:
        raise ValueError(f"Contract field '{field}' min cannot exceed max.")
    return ScoreExpectation(min=minimum, max=maximum)


def _expectation(value: Any, field: str) -> ContractExpectation:
    mapping = _mapping(value, field)
    _reject_unknown(
        mapping,
        {
            "result",
            "functional_tests",
            "score",
            "modified_paths",
            "failed_checks",
            "evidence_patterns",
        },
        field,
    )
    result = _required_string(mapping, "result", field)
    functional_tests = _required_string(mapping, "functional_tests", field)
    for key, item in (("result", result), ("functional_tests", functional_tests)):
        if item not in {"PASS", "FAIL"}:
            raise ValueError(f"Contract field '{field}.{key}' must be PASS or FAIL.")
    return ContractExpectation(
        result=result,
        functional_tests=functional_tests,
        score=_score(mapping.get("score"), f"{field}.score"),
        modified_paths=_patterns(
            mapping.get("modified_paths"),
            f"{field}.modified_paths",
            allowed_key=True,
        ),
        failed_checks=_patterns(
            mapping.get("failed_checks"),
            f"{field}.failed_checks",
        ),
        evidence_patterns=_patterns(
            mapping.get("evidence_patterns"),
            f"{field}.evidence_patterns",
        ),
    )


def load_benchmark_contract(path: Path) -> BenchmarkContract:
    contract_path = path.expanduser()
    with contract_path.open("r", encoding="utf-8") as file:
        data = yaml.load(file, Loader=_StrictSafeLoader) or {}
    mapping = _mapping(data, "contract")
    _reject_unknown(
        mapping,
        {
            "schema",
            "schema_version",
            "benchmark_id",
            "benchmark_version",
            "variants",
        },
        "contract",
    )
    schema = _required_string(mapping, "schema", "contract")
    if schema != CONTRACT_SCHEMA:
        raise ValueError(f"Contract schema must be '{CONTRACT_SCHEMA}'.")
    schema_version = mapping.get("schema_version")
    if schema_version != CONTRACT_SCHEMA_VERSION:
        raise ValueError(
            f"Contract schema_version must be {CONTRACT_SCHEMA_VERSION}."
        )
    benchmark_id = _required_string(mapping, "benchmark_id", "contract")
    benchmark_version = mapping.get("benchmark_version")
    if (
        not isinstance(benchmark_version, int)
        or isinstance(benchmark_version, bool)
        or benchmark_version <= 0
    ):
        raise ValueError("Contract benchmark_version must be a positive integer.")
    raw_variants = _mapping(mapping.get("variants"), "contract.variants")
    if not raw_variants:
        raise ValueError("Contract field 'variants' must not be empty.")
    variants: list[ContractVariant] = []
    for name, raw_variant in raw_variants.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Contract variant names must be non-empty strings.")
        variant = _mapping(raw_variant, f"contract.variants.{name}")
        _reject_unknown(
            variant,
            {"config", "expected"},
            f"contract.variants.{name}",
        )
        config_value = _required_string(
            variant,
            "config",
            f"contract.variants.{name}",
        )
        variants.append(
            ContractVariant(
                name=name,
                config=resolve_project_reference(config_value, contract_path),
                expected=_expectation(
                    variant.get("expected"),
                    f"contract.variants.{name}.expected",
                ),
            )
        )
    return BenchmarkContract(
        path=contract_path,
        schema=schema,
        schema_version=schema_version,
        benchmark_id=benchmark_id,
        benchmark_version=benchmark_version,
        variants=variants,
    )


def _resolved(path: Path) -> Path:
    return path.expanduser().resolve()


def validate_contract_alignment(
    entry: BenchmarkRegistryEntry,
    contract: BenchmarkContract,
) -> None:
    if contract.benchmark_id != entry.id:
        raise ValueError(
            f"Contract {contract.path} benchmark_id '{contract.benchmark_id}' "
            f"does not match registry id '{entry.id}'."
        )
    if contract.benchmark_version != entry.version:
        raise ValueError(
            f"Contract {contract.path} benchmark_version "
            f"{contract.benchmark_version} does not match registry version "
            f"{entry.version}."
        )
    contract_configs = {variant.name: variant.config for variant in contract.variants}
    if set(contract_configs) != set(entry.configs):
        raise ValueError(
            f"Contract {contract.path} variants do not match registry configs."
        )
    for name, config_path in entry.configs.items():
        if _resolved(contract_configs[name]) != _resolved(config_path):
            raise ValueError(
                f"Contract {contract.path} variant '{name}' config does not "
                "match the registry."
            )
        config = load_config(config_path)
        if config.benchmark.version != entry.version:
            raise ValueError(
                f"Config {config_path} benchmark version does not match "
                f"registry version {entry.version}."
            )


def load_registry_contracts(
    registry: BenchmarkRegistry,
) -> list[tuple[BenchmarkRegistryEntry, BenchmarkContract]]:
    pairs = []
    seen_paths: set[Path] = set()
    for entry in registry.benchmarks:
        resolved_path = _resolved(entry.contract)
        if resolved_path in seen_paths:
            raise ValueError(f"Duplicate benchmark contract path: {entry.contract}")
        seen_paths.add(resolved_path)
        contract = load_benchmark_contract(entry.contract)
        validate_contract_alignment(entry, contract)
        pairs.append((entry, contract))

    contract_dirs = {_resolved(entry.contract).parent for entry in registry.benchmarks}
    referenced = {_resolved(entry.contract) for entry in registry.benchmarks}
    discovered = {
        path.resolve()
        for directory in contract_dirs
        for path in directory.glob("*.yaml")
    }
    extras = sorted(discovered - referenced)
    if extras:
        raise ValueError(
            "Unregistered benchmark contract files: "
            + ", ".join(str(path) for path in extras)
        )
    return pairs
