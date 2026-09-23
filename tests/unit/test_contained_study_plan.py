import json
import os
import socket
import subprocess
from importlib import resources
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator, ValidationError
from typer.testing import CliRunner

import agentguard.evaluation.study_plan as study_plan
from agentguard.cli.main import app
from agentguard.evaluation.study_plan import (
    CONTAINED_STUDY_PLAN_SCHEMA,
    ContainedStudyPlanOptions,
    build_contained_study_plan,
    serialize_contained_study_plan,
)


IMAGE = "ghcr.io/example/offline-agent@sha256:" + "b" * 64
runner = CliRunner()


def _profile_data(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "schema": "agentguard.contained-agent-profile",
        "schema_version": 1,
        "id": "offline-profile",
        "display_label": "Offline Profile",
        "image": IMAGE,
        "argv": ["/usr/local/bin/agent", "--task-file", "/workspace/TASK.md"],
        "capabilities": ["python-edit", "read-only"],
        "metadata": {
            "max_cost_usd": 0,
            "max_input_tokens": 1000,
            "max_output_tokens": 500,
        },
    }
    data.update(overrides)
    return data


def _write_profile(tmp_path: Path, name: str = "profile.yaml", **overrides: object) -> Path:
    path = tmp_path / name
    path.write_text(
        yaml.safe_dump(_profile_data(**overrides), sort_keys=False),
        encoding="utf-8",
    )
    return path


def _plan(profile_paths: list[Path], **kwargs: object) -> dict[str, object]:
    plan = build_contained_study_plan(
        ContainedStudyPlanOptions(profile_paths=profile_paths, **kwargs)
    )
    return json.loads(serialize_contained_study_plan(plan))


def test_deterministic_plan_digest_and_trial_ids(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)

    first = _plan([profile], fixture_ids=["safe-bounded-edit"], trials=3)
    second = _plan([profile], fixture_ids=["safe-bounded-edit"], trials=3)

    assert first == second
    assert first["schema"] == CONTAINED_STUDY_PLAN_SCHEMA
    assert first["trial_repetitions_per_unit"] == 3
    assert first["total_planned_trial_count"] == 3
    assert len({trial["trial_id"] for trial in first["trials"]}) == 3
    assert first["plan_digest"] != ""


def test_packaged_json_schema_accepts_plan_and_rejects_unknown(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    data = _plan([profile], fixture_ids=["safe-bounded-edit"], trials=1)
    schema_path = (
        resources.files("agentguard.schemas")
        / "contained-study-plan-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    validator.validate(data)

    invalid = dict(data)
    invalid["provider"] = "example"
    with pytest.raises(ValidationError):
        validator.validate(invalid)


def test_ordering_independence_for_profiles_and_fixtures(tmp_path: Path) -> None:
    alpha = _write_profile(tmp_path, "alpha.yaml", id="alpha-profile")
    beta = _write_profile(tmp_path, "beta.yaml", id="beta-profile")

    first = _plan(
        [beta, alpha],
        fixture_ids=["mutation-boundary", "safe-bounded-edit"],
        trials=1,
    )
    second = _plan(
        [alpha, beta],
        fixture_ids=["safe-bounded-edit", "mutation-boundary"],
        trials=1,
    )

    assert first == second
    assert [profile["id"] for profile in first["profiles"]] == [
        "alpha-profile",
        "beta-profile",
    ]
    assert [fixture["id"] for fixture in first["fixtures"]] == [
        "mutation-boundary",
        "safe-bounded-edit",
    ]


def test_plan_redacts_raw_argv_and_secret_values(tmp_path: Path) -> None:
    profile = _write_profile(
        tmp_path,
        argv=["/opt/private-agent", "--task-file", "/workspace/TASK.md"],
        environment={"unset": ["AGENT_API_TOKEN"]},
    )

    data = _plan([profile], fixture_ids=["read-only-control"], trials=1)
    text = json.dumps(data, sort_keys=True)

    assert "/opt/private-agent" not in text
    assert "/workspace/TASK.md" not in text
    assert "AGENT_API_TOKEN" in text
    assert '"values_recorded": false' in json.dumps(data, sort_keys=True)
    assert data["profiles"][0]["argv"]["raw_disclosed"] is False
    assert "sha256" in data["profiles"][0]["argv"]


def test_no_network_docker_subprocess_or_credential_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _write_profile(tmp_path)

    def fail_socket(*_args, **_kwargs):
        raise AssertionError("network access attempted")

    def fail_popen(*_args, **_kwargs):
        raise AssertionError("subprocess execution attempted")

    class ExplodingEnv(dict):
        def __contains__(self, key: object) -> bool:
            raise AssertionError(f"credential environment read attempted: {key}")

        def get(self, key: object, default: object = None) -> object:
            raise AssertionError(f"credential environment read attempted: {key}")

        def __getitem__(self, key: object) -> object:
            raise AssertionError(f"credential environment read attempted: {key}")

    monkeypatch.setattr(socket, "socket", fail_socket)
    monkeypatch.setattr(subprocess, "Popen", fail_popen)
    monkeypatch.setattr(os, "environ", ExplodingEnv())

    data = _plan([profile], fixture_ids=["safe-bounded-edit"], trials=1)

    assert data["warnings"]
    assert data["total_planned_trial_count"] == 1


@pytest.mark.parametrize(
    "overrides,match",
    [
        ({"network": "bridge"}, "offline-only"),
        ({"environment": {"required": ["AGENT_API_TOKEN"]}}, "must not require"),
        ({"capabilities": ["read-only"]}, "missing capabilities"),
    ],
)
def test_invalid_or_future_live_profiles_are_rejected(
    tmp_path: Path,
    overrides: dict[str, object],
    match: str,
) -> None:
    profile = _write_profile(tmp_path, **overrides)

    with pytest.raises(ValueError, match=match):
        _plan([profile], fixture_ids=["safe-bounded-edit"], trials=1)


def test_duplicate_and_conflicting_input_rejection(tmp_path: Path) -> None:
    first = _write_profile(tmp_path, "first.yaml", id="same-profile")
    second = _write_profile(tmp_path, "second.yaml", id="same-profile")

    with pytest.raises(ValueError, match="profile ids"):
        _plan([first, second], fixture_ids=["safe-bounded-edit"], trials=1)

    with pytest.raises(ValueError, match="fixture selections"):
        _plan([first], fixture_ids=["safe-bounded-edit", "safe-bounded-edit"], trials=1)


@pytest.mark.parametrize(
    "kwargs,match",
    [
        ({"trials": 0}, "trials"),
        ({"trials": 101}, "trials"),
        ({"fixture_ids": ["does-not-exist"]}, "Unknown"),
        ({"fixture_ids": ["safe-bounded-edit"], "trials": True}, "trials"),
    ],
)
def test_malformed_and_hostile_input_bounds(
    tmp_path: Path,
    kwargs: dict[str, object],
    match: str,
) -> None:
    profile = _write_profile(tmp_path)

    with pytest.raises(ValueError, match=match):
        _plan([profile], **kwargs)


def test_excessive_matrix_bounds_fail(tmp_path: Path) -> None:
    profiles = [
        _write_profile(tmp_path, f"profile-{index}.yaml", id=f"profile-{index}")
        for index in range(6)
    ]

    with pytest.raises(ValueError, match="too large"):
        _plan(profiles, trials=30)


def test_duplicate_trial_identity_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _write_profile(tmp_path)
    monkeypatch.setattr(study_plan, "_trial_id", lambda *_args: "trial-" + "0" * 24)

    with pytest.raises(ValueError, match="Duplicate contained study trial id"):
        _plan([profile], fixture_ids=["safe-bounded-edit"], trials=2)


def test_portable_artifact_aliases_and_fixture_hashes(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)

    data = _plan([profile], fixture_ids=["safe-bounded-edit"], trials=1)
    text = json.dumps(data, sort_keys=True)

    assert str(tmp_path) not in text
    assert data["trials"][0]["artifact_alias"].startswith("contained-study/")
    assert data["fixtures"][0]["fixture_hash"]
    assert data["fixtures"][0]["prompt_sha256"]


def test_cli_help_and_json_output(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)

    help_result = runner.invoke(app, ["evaluation", "study-plan", "--help"])
    assert help_result.exit_code == 0
    assert "without execution" in help_result.output

    result = runner.invoke(
        app,
        [
            "evaluation",
            "study-plan",
            "--profile",
            str(profile),
            "--fixture",
            "read-only-control",
            "--trials",
            "1",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["total_planned_trial_count"] == 1


def test_cli_controlled_error_and_output_file(tmp_path: Path) -> None:
    missing = runner.invoke(app, ["evaluation", "study-plan", "--trials", "1"])
    assert missing.exit_code == 2
    assert "At least one contained agent profile" in missing.output

    profile = _write_profile(tmp_path)
    output = tmp_path / "plan.json"
    result = runner.invoke(
        app,
        [
            "evaluation",
            "study-plan",
            "--profile",
            str(profile),
            "--fixture",
            "read-only-control",
            "--trials",
            "1",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert "Plan digest:" in result.output
    assert json.loads(output.read_text(encoding="utf-8"))["plan_digest"]
