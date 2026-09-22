import json
from importlib import resources
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator, ValidationError

from agentguard.config.loader import load_config
from agentguard.evaluation.contained_profile import (
    contained_agent_profile_diagnostics,
    load_contained_agent_profile,
    serialize_contained_agent_profile,
)


IMAGE = "ghcr.io/example/agent@sha256:" + "a" * 64


def _write_profile(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "contained-profile.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def _minimal_profile(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "schema": "agentguard.contained-agent-profile",
        "schema_version": 1,
        "id": "offline-profile",
        "display_label": "Offline Profile",
        "image": IMAGE,
        "argv": ["/usr/local/bin/agent", "--task-file", "/workspace/TASK.md"],
    }
    data.update(overrides)
    return data


def _write_yaml_profile(tmp_path: Path, **overrides: object) -> Path:
    return _write_profile(
        tmp_path,
        yaml.safe_dump(_minimal_profile(**overrides), sort_keys=False),
    )


def test_valid_minimal_offline_profile_defaults_are_deterministic(tmp_path: Path) -> None:
    profile = load_contained_agent_profile(_write_yaml_profile(tmp_path))

    assert profile.id == "offline-profile"
    assert profile.network == "none"
    assert profile.environment.required == []
    assert profile.environment.unset == []
    assert profile.limits.timeout_seconds == 60
    assert profile.limits.cpu_limit == 1.0
    assert profile.limits.memory_limit == "512m"
    assert profile.limits.pids_limit == 256

    first = serialize_contained_agent_profile(profile)
    second = serialize_contained_agent_profile(profile)
    assert first == second
    assert json.loads(first)["environment"]["required"] == []


def test_packaged_json_schema_accepts_minimal_profile_and_rejects_unknown() -> None:
    schema_path = (
        resources.files("agentguard.schemas")
        / "contained-agent-profile-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    document = _minimal_profile()
    validator.validate(document)

    invalid = {**document, "docker_flags": ["--privileged"]}
    with pytest.raises(ValidationError):
        validator.validate(invalid)


def test_valid_bounded_optional_metadata_and_identity(tmp_path: Path) -> None:
    profile = load_contained_agent_profile(
        _write_yaml_profile(
            tmp_path,
            environment={"required": ["AGENT_API_TOKEN"], "unset": ["HTTP_PROXY"]},
            network="bridge",
            limits={
                "timeout_seconds": 120,
                "cpu_limit": 2.0,
                "memory_limit": "1g",
                "pids_limit": 512,
                "max_output_bytes": 1048576,
            },
            metadata={
                "max_cost_usd": 3.5,
                "max_input_tokens": 100000,
                "max_output_tokens": 20000,
            },
            capabilities=["python-edit", "read-only"],
            identity={
                "agent_name": "Example Agent",
                "agent_version": "2026.9",
                "evidence_source": "profile-declared",
            },
        )
    )

    assert profile.environment.required == ["AGENT_API_TOKEN"]
    assert profile.environment.unset == ["HTTP_PROXY"]
    assert profile.network == "bridge"
    assert profile.capabilities == ["python-edit", "read-only"]
    assert profile.metadata.max_cost_usd == 3.5
    diagnostics = contained_agent_profile_diagnostics(profile)
    assert diagnostics["environment"]["values_recorded"] is False
    assert "argv_sha256" in diagnostics
    assert "Example Agent" not in json.dumps(diagnostics)


@pytest.mark.parametrize(
    "override,match",
    [
        ({"schema_version": 2}, "Unsupported"),
        ({"schema_version": None}, "Unsupported"),
        ({"id": "../bad"}, "portable"),
        ({"id": ""}, "non-empty"),
        ({"display_label": ""}, "non-empty"),
    ],
)
def test_missing_or_invalid_version_and_identifier(
    tmp_path: Path,
    override: dict[str, object],
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        load_contained_agent_profile(_write_yaml_profile(tmp_path, **override))


@pytest.mark.parametrize(
    "image",
    [
        "ghcr.io/example/agent:latest",
        "ghcr.io/example/agent",
        "ghcr.io/example/agent:1.0",
    ],
)
def test_mutable_image_rejection(tmp_path: Path, image: str) -> None:
    with pytest.raises(ValueError, match="immutable @sha256"):
        load_contained_agent_profile(_write_yaml_profile(tmp_path, image=image))


@pytest.mark.parametrize(
    "argv,match",
    [
        (["bash", "-lc", "agent run"], "must not invoke a shell"),
        (["agent", "run && leak"], "structured tokens"),
        (["agent", "--api-key", "literal-value"], "approved environment name"),
        (["agent", "--api-key=literal-value"], "inline credential"),
        (["agent", "https://user:pass@example.test"], "URL credentials"),
    ],
)
def test_shell_string_and_unsafe_argv_rejection(
    tmp_path: Path,
    argv: list[str],
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        load_contained_agent_profile(_write_yaml_profile(tmp_path, argv=argv))


def test_credential_option_may_reference_required_environment_name(tmp_path: Path) -> None:
    profile = load_contained_agent_profile(
        _write_yaml_profile(
            tmp_path,
            argv=["agent", "--api-key", "AGENT_API_TOKEN"],
            environment={"required": ["AGENT_API_TOKEN"]},
        )
    )

    assert profile.argv == ["agent", "--api-key", "AGENT_API_TOKEN"]
    assert "AGENT_API_TOKEN" in serialize_contained_agent_profile(profile)


@pytest.mark.parametrize(
    "environment,match",
    [
        ({"required": ["AGENT_TOKEN", "AGENT_TOKEN"]}, "duplicate"),
        ({"required": ["AGENT_TOKEN"], "unset": ["AGENT_TOKEN"]}, "both required and unset"),
        ({"required": ["bad-name"]}, "uppercase"),
        ({"unset": ["BAD\x00NAME"]}, "control"),
    ],
)
def test_duplicate_and_conflicting_env_names(
    tmp_path: Path,
    environment: dict[str, list[str]],
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        load_contained_agent_profile(
            _write_yaml_profile(tmp_path, environment=environment)
        )


@pytest.mark.parametrize(
    "override,match",
    [
        ({"argv": ["agent", "sk-abc123456789"]}, "secret value"),
        ({"identity": {"agent_version": "Bearer literal-token"}}, "secret value"),
        ({"metadata": {"api_key": "value"}}, "Unknown config field"),
        ({"environment": {"required": ["AGENT_TOKEN"], "TOKEN_VALUE": "secret"}}, "Unknown"),
    ],
)
def test_inline_secret_value_rejection(
    tmp_path: Path,
    override: dict[str, object],
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        load_contained_agent_profile(_write_yaml_profile(tmp_path, **override))


@pytest.mark.parametrize(
    "network,match",
    [
        ("host", "must not be host"),
        ("container:abc", "must be one of"),
        (True, "must be a string"),
    ],
)
def test_invalid_network_mode_and_host_network_rejection(
    tmp_path: Path,
    network: object,
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        load_contained_agent_profile(_write_yaml_profile(tmp_path, network=network))


@pytest.mark.parametrize(
    "limits,match",
    [
        ({"timeout_seconds": 0}, "timeout_seconds"),
        ({"cpu_limit": 0.01}, "cpu_limit"),
        ({"memory_limit": "1m"}, "outside"),
        ({"pids_limit": 1}, "pids_limit"),
        ({"max_output_bytes": 1}, "max_output_bytes"),
    ],
)
def test_bounds_rejection(tmp_path: Path, limits: dict[str, object], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        load_contained_agent_profile(_write_yaml_profile(tmp_path, limits=limits))


def test_control_characters_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="control"):
        load_contained_agent_profile(
            _write_yaml_profile(tmp_path, display_label="Bad\x1fLabel")
        )


def test_unknown_field_handling(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="docker_flags"):
        load_contained_agent_profile(
            _write_yaml_profile(tmp_path, docker_flags=["--privileged"])
        )


def test_duplicate_yaml_keys_are_rejected(tmp_path: Path) -> None:
    path = _write_profile(
        tmp_path,
        f"""
schema: agentguard.contained-agent-profile
schema_version: 1
id: offline-profile
id: other-profile
display_label: Offline Profile
image: {IMAGE}
argv: [agent]
""",
    )

    with pytest.raises(yaml.constructor.ConstructorError, match="duplicate key"):
        load_contained_agent_profile(path)


def test_deterministic_parse_serialize_ordering(tmp_path: Path) -> None:
    first = load_contained_agent_profile(
        _write_yaml_profile(
            tmp_path,
            environment={"unset": ["BETA"], "required": ["ALPHA"]},
            capabilities=["read-only", "python-edit"],
        )
    )
    second = load_contained_agent_profile(
        _write_yaml_profile(
            tmp_path,
            capabilities=["python-edit", "read-only"],
            environment={"required": ["ALPHA"], "unset": ["BETA"]},
        )
    )

    assert serialize_contained_agent_profile(first) == serialize_contained_agent_profile(second)


def test_no_effect_on_existing_contained_run_configuration(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        f"""
task_id: contained_profile_compat
description: Compatibility fixture.
repo_template: examples/repos/auth_bug
test_command: python3 -m auth_example.mini_pytest
sandbox:
  type: docker
  image: {IMAGE}
contained_execution:
  version: 1
  platform: linux-docker-engine
  network: none
  image_provenance: digest-required
  required_uid: 1000
  required_gid: 1000
  environment: []
allowed_paths: [src/**]
forbidden_paths: [.env]
test_paths: [tests/**]
expected_modified_files: {{min: 0, max: 2}}
unsafe_commands: []
policy: {{}}
diff_limits: {{}}
secret_patterns: []
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.contained_execution is not None
    assert config.contained_execution.network == "none"
    assert config.sandbox.image == IMAGE


def test_no_secret_values_in_serialized_diagnostics(tmp_path: Path) -> None:
    profile = load_contained_agent_profile(
        _write_yaml_profile(
            tmp_path,
            argv=["agent", "--api-key", "AGENT_API_TOKEN"],
            environment={"required": ["AGENT_API_TOKEN"]},
        )
    )
    diagnostics = contained_agent_profile_diagnostics(profile)
    rendered = json.dumps(diagnostics, sort_keys=True)

    assert "secret" not in rendered.lower()
    assert "literal-value" not in rendered
    assert diagnostics["environment"]["values_recorded"] is False
