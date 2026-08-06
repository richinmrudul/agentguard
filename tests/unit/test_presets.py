import json
import re
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.presets import (
    DEFAULT_PRESET_NAME,
    PRESET_REGISTRY,
    PRESETS,
    PolicyPreset,
    _registry_by_name,
    get_preset,
    preset_names,
)


runner = CliRunner()
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SEVERITY_RANK = {"info": 0, "warning": 1, "error": 2, "critical": 3}


def _error_output(result) -> str:
    try:
        return result.stderr
    except ValueError:
        return result.output


def _captured_output(result) -> str:
    streams = []
    for attribute in ("stdout", "stderr"):
        try:
            streams.append(getattr(result, attribute))
        except ValueError:
            pass
    return "\n".join(streams) or result.output


def test_registry_contains_exactly_three_stable_presets() -> None:
    assert preset_names() == ("minimal", "recommended", "strict")
    assert tuple(PRESET_REGISTRY) == preset_names()
    assert DEFAULT_PRESET_NAME == "recommended"
    assert [preset.name for preset in PRESETS if preset.default] == ["recommended"]


def test_registry_and_definitions_are_immutable_and_reject_duplicates() -> None:
    with pytest.raises(TypeError):
        PRESET_REGISTRY["other"] = PRESETS[0]  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        PRESETS[0].name = "other"  # type: ignore[misc]
    duplicate = PolicyPreset(
        name=PRESETS[0].name,
        summary="duplicate",
        intended_use="duplicate",
        validation_posture="duplicate",
        requirements=(),
        limitations=(),
        settings=PRESETS[0].settings,
    )
    with pytest.raises(ValueError, match="unique"):
        _registry_by_name((PRESETS[0], duplicate))


def test_objectively_ordered_settings_are_monotonic() -> None:
    minimal = get_preset("minimal").settings
    recommended = get_preset("recommended").settings
    strict = get_preset("strict").settings

    assert (
        minimal.command_timeout_seconds
        >= recommended.command_timeout_seconds
        >= strict.command_timeout_seconds
    )
    assert (
        minimal.max_output_bytes
        >= recommended.max_output_bytes
        >= strict.max_output_bytes
    )
    assert (
        minimal.expected_modified_files_max
        >= recommended.expected_modified_files_max
        >= strict.expected_modified_files_max
    )
    for field in ("max_files_changed", "max_lines_added", "max_lines_deleted"):
        assert (
            getattr(minimal, field)
            >= getattr(recommended, field)
            >= getattr(strict, field)
        )
    for weaker, stronger in ((minimal, recommended), (recommended, strict)):
        weaker_policy = dict(weaker.policy_severities)
        stronger_policy = dict(stronger.policy_severities)
        assert weaker_policy.keys() == stronger_policy.keys()
        assert all(
            SEVERITY_RANK[stronger_policy[key]] >= SEVERITY_RANK[severity]
            for key, severity in weaker_policy.items()
        )
        assert set(stronger.secret_content_builtin_detectors).issuperset(
            weaker.secret_content_builtin_detectors
        )


def test_public_settings_exclude_ci_ignored_controls() -> None:
    ignored = {
        "sandbox",
        "docker",
        "command_policy",
        "filesystem_watcher",
        "benchmark",
        "agent_command",
    }
    for preset in PRESETS:
        settings = preset.as_public_mapping()["settings"]
        assert ignored.isdisjoint(settings)
        assert settings["mode"] == "ci"
        assert preset.as_public_mapping()["suitable_for_untrusted_code"] is False


def test_preset_list_is_human_readable_and_states_execution_boundary() -> None:
    result = runner.invoke(app, ["presets", "list"])

    assert result.exit_code == 0, result.output
    for name in preset_names():
        assert f"- {name}" in result.output
    assert "recommended (default)" in result.output
    assert "none of these presets contains agent execution" in result.output


@pytest.mark.parametrize("name", preset_names())
def test_preset_show_text_explains_truthful_posture(name: str) -> None:
    result = runner.invoke(app, ["presets", "show", name])

    assert result.exit_code == 0, result.output
    assert f"AgentGuard preset: {name}" in result.output
    assert "CI-consumed settings:" in result.output
    assert "no execution containment" in result.output
    assert "Suitable for untrusted code: no" in result.output


@pytest.mark.parametrize("output_format", ["yaml", "json"])
@pytest.mark.parametrize("name", preset_names())
def test_machine_output_is_deterministic_parseable_and_control_free(
    name: str,
    output_format: str,
) -> None:
    first = runner.invoke(app, ["presets", "show", name, "--format", output_format])
    second = runner.invoke(app, ["presets", "show", name, "--format", output_format])

    assert first.exit_code == second.exit_code == 0
    assert first.stdout == second.stdout
    assert not ANSI.search(first.stdout)
    data = (
        json.loads(first.stdout)
        if output_format == "json"
        else yaml.safe_load(first.stdout)
    )
    assert data == get_preset(name).as_public_mapping()
    serialized = json.dumps(data, sort_keys=True)
    for forbidden in ("timestamp", "environment", "/Users/", "C:\\"):
        assert forbidden not in serialized


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (
            ("presets", "show", "Recommended"),
            "Valid presets: minimal, recommended, strict",
        ),
        (("presets", "show", "missing"), "Valid presets: minimal, recommended, strict"),
        (
            ("presets", "show", "minimal", "--format", "toml"),
            "Valid formats: text, yaml, json",
        ),
    ],
)
def test_preset_mistakes_are_concise_stderr_errors(
    args: tuple[str, ...], message: str
) -> None:
    result = runner.invoke(app, list(args))

    assert result.exit_code == 2
    assert message in _error_output(result)
    assert "Traceback" not in result.output


def test_preset_help_is_discoverable() -> None:
    root_help = runner.invoke(app, ["--help"])
    show_help = runner.invoke(app, ["presets", "show", "--help"])

    assert root_help.exit_code == show_help.exit_code == 0
    root_output = _captured_output(root_help)
    show_output = _captured_output(show_help)
    assert "presets" in root_output
    assert "--format" in show_output
    assert "text, yaml, or json" in show_output


def test_documented_comparison_matches_registry_and_rejects_containment_claims() -> (
    None
):
    page = Path("docs/policy-presets.md").read_text(encoding="utf-8")
    initializer = Path("docs/project-initialization.md").read_text(encoding="utf-8")
    github_actions = Path("docs/github-actions.md").read_text(encoding="utf-8")
    combined = "\n".join((page, initializer, github_actions)).lower()

    for preset in PRESETS:
        settings = preset.settings
        assert f"`{preset.name}`" in page
        assert f"{settings.command_timeout_seconds} seconds" in page
        assert f"{settings.max_output_bytes:,} bytes" in page
    assert "does not contain" in combined
    assert "`untrusted-agent` preset is intentionally not available" in page
    for unsupported_claim in (
        "fully sandboxed",
        "maximum security",
        "prevents every secret leak",
        "guarantees safe behavior",
    ):
        assert unsupported_claim not in combined


def test_policy_preset_page_is_in_mkdocs_navigation() -> None:
    mkdocs = Path("mkdocs.yml").read_text(encoding="utf-8")
    assert "CI Policy Presets: policy-presets.md" in mkdocs
