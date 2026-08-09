import json
from importlib import resources
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator, ValidationError

from agentguard.checks.secret_content import BUILTIN_SECRET_CONTENT_DETECTORS
from agentguard.config.json_schema import (
    CONFIG_SCHEMA_FILENAME,
    CONFIG_SCHEMA_VERSION,
    load_config_json_schema,
)
from agentguard.config.loader import (
    POLICY_KEYS,
    TOP_LEVEL_CONFIG_KEYS,
    VALID_AGENT_WORKDIRS,
    VALID_COMMAND_POLICY_MODES,
    VALID_DOCKER_NETWORKS,
    VALID_FILESYSTEM_WATCHER_MODES,
    load_config,
)
from agentguard.config.schema import (
    VALID_BENCHMARK_DIFFICULTIES,
    VALID_SEVERITIES,
)


ROOT = Path(__file__).resolve().parents[2]


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
    assert set(schema["required"]) == {
        "task_id",
        "description",
        "test_command",
        "expected_modified_files",
    }


def test_schema_enums_match_production_constants(schema: dict) -> None:
    properties = schema["properties"]
    definitions = schema["$defs"]
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
    assert paths
    for config_path in paths:
        with config_path.open("r", encoding="utf-8") as stream:
            validator.validate(yaml.safe_load(stream))
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
