import json
from importlib import resources
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator, ValidationError

from agentguard.artifact_paths import PORTABLE_ID_PATTERN
from agentguard.checks.secret_content import BUILTIN_SECRET_CONTENT_DETECTORS
from agentguard.config.json_schema import (
    CONFIG_SCHEMA_FILENAME,
    CONFIG_SCHEMA_VERSION,
    load_config_json_schema,
)
from agentguard.config.loader import (
    BENCHMARK_KEYS,
    COMMAND_POLICY_KEYS,
    DIFF_LIMIT_KEYS,
    EXPECTED_MODIFIED_FILES_KEYS,
    EXPECTED_MODIFIED_FILES_REQUIRED_KEYS,
    FILESYSTEM_WATCHER_KEYS,
    MAX_SECRET_CONTENT_LITERAL_LENGTH,
    MAX_SECRET_CONTENT_PATTERNS,
    MAX_SECRET_CONTENT_PATTERN_ID_LENGTH,
    MIN_SECRET_CONTENT_LITERAL_LENGTH,
    POLICY_KEYS,
    POLICY_SETTING_KEYS,
    POSITIVE_FLOAT_STRING_PATTERN,
    REQUIRED_STRING_FIELDS,
    SANDBOX_DOCKER_KEYS,
    SANDBOX_KEYS,
    SECRET_CONTENT_PATTERN_ID,
    SECRET_CONTENT_PATTERN_KEYS,
    TASK_KEYS,
    TOP_LEVEL_CONFIG_KEYS,
    TOP_LEVEL_REQUIRED_FIELDS,
    VALID_AGENT_WORKDIRS,
    VALID_COMMAND_POLICY_MODES,
    VALID_CONFIG_MODES,
    VALID_DOCKER_NETWORKS,
    VALID_FILESYSTEM_WATCHER_MODES,
    VALID_SANDBOX_TYPES,
    load_config,
)
from agentguard.config.schema import (
    VALID_BENCHMARK_DIFFICULTIES,
    VALID_SEVERITIES,
)


ROOT = Path(__file__).resolve().parents[2]


def _ci_config(**overrides: object) -> dict:
    document = {
        "task_id": "schema_test",
        "description": "Schema test.",
        "mode": "ci",
        "test_command": "pytest",
        "expected_modified_files": {"min": 0, "max": 2},
    }
    document.update(overrides)
    return document


def _secret_content_patterns(count: int) -> list[dict[str, str]]:
    return [
        {"id": f"detector-{index}", "contains": f"SECRET_TOKEN_{index:03d}"}
        for index in range(count)
    ]


def _builtin_secret_content_detectors(count: int) -> list[str]:
    return sorted(BUILTIN_SECRET_CONTENT_DETECTORS)[:count]


@pytest.fixture(scope="module")
def schema() -> dict:
    value = load_config_json_schema()
    Draft202012Validator.check_schema(value)
    return value


def test_schema_is_versioned_draft_2020_12_and_deterministic(schema: dict) -> None:
    assert CONFIG_SCHEMA_VERSION == 1
    assert CONFIG_SCHEMA_FILENAME == "agentguard-config-v1.schema.json"
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"].endswith(f"/{CONFIG_SCHEMA_FILENAME}")
    assert "timestamp" not in json.dumps(schema).lower()


def test_schema_top_level_contract_matches_production_loader(schema: dict) -> None:
    assert set(schema["properties"]) == TOP_LEVEL_CONFIG_KEYS
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == TOP_LEVEL_REQUIRED_FIELDS
    assert set(REQUIRED_STRING_FIELDS) < TOP_LEVEL_REQUIRED_FIELDS


def test_schema_enums_match_production_constants(schema: dict) -> None:
    properties = schema["properties"]
    definitions = schema["$defs"]
    assert set(properties["mode"]["enum"]) == VALID_CONFIG_MODES
    assert set(properties["agent_workdir"]["enum"]) == VALID_AGENT_WORKDIRS
    assert set(
        properties["command_policy"]["properties"]["mode"]["enum"]
    ) == VALID_COMMAND_POLICY_MODES
    assert set(definitions["filesystemWatcherMode"]["enum"]) == (
        VALID_FILESYSTEM_WATCHER_MODES
    )
    assert set(
        definitions["sandbox"]["properties"]["network"]["enum"]
    ) == VALID_DOCKER_NETWORKS
    assert set(definitions["sandbox"]["properties"]["type"]["enum"]) == (
        VALID_SANDBOX_TYPES
    )
    assert set(
        properties["benchmark"]["properties"]["difficulty"]["enum"]
    ) == VALID_BENCHMARK_DIFFICULTIES | {None}
    assert set(
        definitions["policySetting"]["properties"]["severity"]["enum"]
    ) == VALID_SEVERITIES | {None}
    assert set(properties["policy"]["properties"]) == POLICY_KEYS
    assert set(
        properties["secret_content_builtin_detectors"]["items"]["enum"]
    ) == set(BUILTIN_SECRET_CONTENT_DETECTORS)


def test_schema_bounds_and_nested_keys_match_loader_constants(schema: dict) -> None:
    properties = schema["properties"]
    definitions = schema["$defs"]
    task_id = properties["task_id"]
    secret_pattern = definitions["secretContentPattern"]

    assert task_id["pattern"] == PORTABLE_ID_PATTERN.pattern
    assert task_id["maxLength"] == 128
    assert properties["secret_content_builtin_detectors"]["maxItems"] == (
        MAX_SECRET_CONTENT_PATTERNS
    )
    assert properties["secret_content_patterns"]["maxItems"] == (
        MAX_SECRET_CONTENT_PATTERNS
    )
    assert set(secret_pattern["properties"]) == SECRET_CONTENT_PATTERN_KEYS
    assert set(secret_pattern["required"]) == SECRET_CONTENT_PATTERN_KEYS
    assert secret_pattern["properties"]["id"]["maxLength"] == (
        MAX_SECRET_CONTENT_PATTERN_ID_LENGTH
    )
    assert secret_pattern["properties"]["id"]["pattern"] == (
        SECRET_CONTENT_PATTERN_ID.pattern
    )
    assert secret_pattern["properties"]["contains"]["minLength"] == (
        MIN_SECRET_CONTENT_LITERAL_LENGTH
    )
    assert secret_pattern["properties"]["contains"]["maxLength"] == (
        MAX_SECRET_CONTENT_LITERAL_LENGTH
    )

    nested_contracts = [
        (properties["task"], TASK_KEYS),
        (properties["benchmark"], BENCHMARK_KEYS),
        (properties["expected_modified_files"], EXPECTED_MODIFIED_FILES_KEYS),
        (properties["policy"], POLICY_KEYS),
        (definitions["policySetting"], POLICY_SETTING_KEYS),
        (properties["diff_limits"], DIFF_LIMIT_KEYS),
        (properties["command_policy"], COMMAND_POLICY_KEYS),
        (definitions["sandbox"], SANDBOX_KEYS),
        (definitions["sandbox"]["properties"]["docker"], SANDBOX_DOCKER_KEYS),
    ]
    for nested_schema, loader_keys in nested_contracts:
        assert nested_schema["additionalProperties"] is False
        assert set(nested_schema["properties"]) == loader_keys
    watcher_object = properties["filesystem_watcher"]["oneOf"][1]
    assert watcher_object["additionalProperties"] is False
    assert set(watcher_object["properties"]) == FILESYSTEM_WATCHER_KEYS
    assert set(properties["expected_modified_files"]["required"]) == (
        EXPECTED_MODIFIED_FILES_REQUIRED_KEYS
    )
    assert definitions["nullableNonNegativeInteger"]["minimum"] == 0
    assert properties["command_timeout_seconds"]["minimum"] == 1
    assert properties["max_output_bytes"]["minimum"] == 1
    assert (
        definitions["sandbox"]["properties"]["docker"]["properties"]["cpus"]
        ["oneOf"][1]["pattern"]
        == POSITIVE_FLOAT_STRING_PATTERN.pattern
    )


def test_every_public_property_has_a_description(schema: dict) -> None:
    def inspect(node: object, path: str) -> None:
        if not isinstance(node, dict):
            return
        properties = node.get("properties", {})
        for name, subschema in properties.items():
            assert "description" in subschema, f"missing description: {path}.{name}"
            inspect(subschema, f"{path}.{name}")
        for keyword in ("$defs", "allOf", "anyOf", "oneOf"):
            child = node.get(keyword, {})
            values = child.values() if isinstance(child, dict) else child
            for subschema in values:
                inspect(subschema, path)

    inspect(schema, "config")


def test_all_maintained_examples_validate_with_schema_and_loader(schema: dict) -> None:
    validator = Draft202012Validator(schema)
    paths = sorted((ROOT / "examples" / "configs").glob("*.yaml"))
    assert len(paths) == 40
    for config_path in paths:
        with config_path.open("r", encoding="utf-8") as stream:
            validator.validate(yaml.safe_load(stream))
        load_config(config_path)


@pytest.mark.parametrize(
    ("builtins", "custom", "accepted"),
    [
        (0, 0, True),
        (0, MAX_SECRET_CONTENT_PATTERNS, True),
        (len(BUILTIN_SECRET_CONTENT_DETECTORS), 0, True),
        (len(BUILTIN_SECRET_CONTENT_DETECTORS), 27, True),
        (len(BUILTIN_SECRET_CONTENT_DETECTORS), 28, False),
        (1, MAX_SECRET_CONTENT_PATTERNS - 1, True),
        (1, MAX_SECRET_CONTENT_PATTERNS, False),
    ],
)
def test_secret_content_detector_combined_limit_schema_loader_parity(
    schema: dict,
    tmp_path: Path,
    builtins: int,
    custom: int,
    accepted: bool,
) -> None:
    document = _ci_config(secret_content_patterns=_secret_content_patterns(custom))
    if builtins:
        document["secret_content_builtin_detectors"] = (
            _builtin_secret_content_detectors(builtins)
        )

    validator = Draft202012Validator(schema)
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(yaml.safe_dump(document), encoding="utf-8")

    assert validator.is_valid(document) is accepted
    if accepted:
        load_config(config_path)
    else:
        with pytest.raises(ValueError, match="exceed the maximum"):
            load_config(config_path)


def test_secret_content_detector_combined_limit_allows_empty_or_omitted_collections(
    schema: dict,
    tmp_path: Path,
) -> None:
    validator = Draft202012Validator(schema)
    documents = [
        _ci_config(),
        _ci_config(secret_content_builtin_detectors=[]),
        _ci_config(secret_content_patterns=[]),
        _ci_config(
            secret_content_builtin_detectors=[],
            secret_content_patterns=_secret_content_patterns(
                MAX_SECRET_CONTENT_PATTERNS
            ),
        ),
    ]

    for index, document in enumerate(documents):
        validator.validate(document)
        config_path = tmp_path / f"agentguard-{index}.yaml"
        config_path.write_text(yaml.safe_dump(document), encoding="utf-8")
        load_config(config_path)


def test_packaged_schema_enforces_combined_detector_limit_like_source_schema() -> None:
    source_schema_path = ROOT / "agentguard" / "schemas" / CONFIG_SCHEMA_FILENAME
    source_schema = json.loads(source_schema_path.read_text(encoding="utf-8"))
    packaged_schema = load_config_json_schema()
    document = _ci_config(
        secret_content_builtin_detectors=_builtin_secret_content_detectors(
            len(BUILTIN_SECRET_CONTENT_DETECTORS)
        ),
        secret_content_patterns=_secret_content_patterns(28),
    )

    assert Draft202012Validator(source_schema).is_valid(document) is False
    assert Draft202012Validator(packaged_schema).is_valid(document) is False


@pytest.mark.parametrize(
    "document",
    [
        _ci_config(),
        _ci_config(repo_template="examples/repos/auth_bug"),
        _ci_config(sandbox={"docker": {"cpus": "1e3"}}),
        _ci_config(filesystem_watcher="polling"),
        _ci_config(task={"prompt": "Review the change."}),
        _ci_config(
            benchmark={
                "id": "schema_test",
                "version": "2",
                "difficulty": "easy",
                "tags": ["schema"],
            }
        ),
        _ci_config(
            secret_content_patterns=[
                {"id": "project-token", "contains": "PROJECT_TOKEN_"}
            ]
        ),
    ],
)
def test_representative_valid_documents_have_loader_schema_parity(
    schema: dict,
    tmp_path: Path,
    document: dict,
) -> None:
    Draft202012Validator(schema).validate(document)
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(yaml.safe_dump(document), encoding="utf-8")
    load_config(config_path)


@pytest.mark.parametrize(
    "document",
    [
        _ci_config(repo_template=""),
        _ci_config(repo_template=None),
        _ci_config(mode="benchmark"),
        _ci_config(task_id="a" * 129),
        _ci_config(expected_modified_files={"max": 2}),
        _ci_config(expected_modified_files={"min": 0, "max": 2, "limit": 3}),
        _ci_config(task={}),
        _ci_config(task={"prompt": "Do it.", "prompt_file": "prompt.txt"}),
        _ci_config(task={"prompt": "Do it.", "extra": True}),
        _ci_config(benchmark={"difficulty": "expert"}),
        _ci_config(benchmark={"dificulty": "easy"}),
        _ci_config(policy={"tests_pass": {"severity": "fatal"}}),
        _ci_config(policy={"tests_pass": {"level": "error"}}),
        _ci_config(command_policy={"mode": "monitor"}),
        _ci_config(filesystem_watcher={"mode": "native"}),
        _ci_config(diff_limits={"max_files_changed": -1}),
        _ci_config(command_timeout_seconds=0),
        _ci_config(sandbox={"type": "docker"}),
        _ci_config(sandbox={"unknown": True}),
        _ci_config(sandbox={"docker": {"unknown": True}}),
        _ci_config(sandbox={"docker": {"cpus": 0}}),
        _ci_config(sandbox={"docker": {"cpus": -1}}),
        _ci_config(sandbox={"docker": {"cpus": "0"}}),
        _ci_config(sandbox={"docker": {"cpus": "-1"}}),
        _ci_config(sandbox={"docker": {"cpus": "nan"}}),
        _ci_config(sandbox={"docker": {"cpus": "1e100"}}),
        _ci_config(
            secret_content_patterns=[
                {"id": "A", "contains": "PROJECT_TOKEN_"}
            ]
        ),
        _ci_config(
            secret_content_patterns=[
                {"id": "a" * 65, "contains": "PROJECT_TOKEN_"}
            ]
        ),
        _ci_config(
            secret_content_patterns=[{"id": "short", "contains": "1234567"}]
        ),
        _ci_config(
            secret_content_patterns=[
                {"id": f"detector-{index}", "contains": f"SECRET_{index:03d}"}
                for index in range(33)
            ]
        ),
    ],
)
def test_representative_invalid_documents_have_loader_schema_parity(
    schema: dict,
    tmp_path: Path,
    document: dict,
) -> None:
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(document)
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(yaml.safe_dump(document), encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(config_path)


@pytest.mark.parametrize(
    "fragment",
    [
        "unknown_field: true",
        "policy:\n  tests_pass:\n    level: error",
        "mode: benchmark",
        "mode: ci\nsandbox:\n  type: docker",
    ],
)
def test_schema_rejects_unsupported_or_incomplete_contracts(
    schema: dict,
    fragment: str,
) -> None:
    document = yaml.safe_load(
        "task_id: schema_test\n"
        "description: Schema test.\n"
        "test_command: pytest\n"
        "expected_modified_files: {min: 0, max: 1}\n"
        f"{fragment}\n"
    )
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(document)


def test_packaged_schema_resource_is_the_canonical_file(schema: dict) -> None:
    resource = resources.files("agentguard.schemas").joinpath(CONFIG_SCHEMA_FILENAME)
    assert json.loads(resource.read_text(encoding="utf-8")) == schema
