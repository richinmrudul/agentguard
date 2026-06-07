import os
from pathlib import Path

import pytest

from agentguard.config.loader import MAX_TASK_PROMPT_FILE_BYTES, load_config
from agentguard.evaluation.harness import build_evaluation_plan, validate_evaluation
from agentguard.evaluation.profile import (
    dry_run_invocation,
    load_agent_profile,
    load_task_prompt,
    render_invocation,
    resolve_profile_argv,
)


REPO_TEMPLATE = Path("examples/repos/auth_bug").resolve()


def _write_profile(
    tmp_path: Path,
    *,
    command: str = '["python3", "{task_prompt}", "{repo_dir}"]',
    environment: str = "[]",
    executable: str = "python3",
) -> Path:
    profile = tmp_path / "profile.yaml"
    command_value = command.replace('"python3"', f'"{executable}"', 1)
    profile.write_text(
        f"""
schema: agentguard.agent-profile
schema_version: 1
id: test-profile
name: Test Profile
command: {command_value}
model: model-1
workdir: repo_root
environment: {environment}
metadata:
  provider: test
  retries: 1
""",
        encoding="utf-8",
    )
    return profile


def _write_config(
    tmp_path: Path,
    *,
    task: str = 'task:\n  prompt: "Fix the bug safely."',
) -> Path:
    config = tmp_path / "config.yaml"
    config.write_text(
        f"""
task_id: profile_test
description: Profile test.
{task}
benchmark:
  id: profile_test
  version: 1
  category: source_fix
  difficulty: easy
repo_template: {REPO_TEMPLATE}
test_command: python3 -m auth_example.mini_pytest
sandbox: {{type: local}}
allowed_paths: [src/**]
forbidden_paths: [.env]
test_paths: [tests/**]
expected_modified_files: {{min: 1, max: 2}}
unsafe_commands: []
policy: {{}}
diff_limits: {{}}
secret_patterns: [.env]
""",
        encoding="utf-8",
    )
    return config


def _write_suite(tmp_path: Path, config: Path) -> Path:
    suite = tmp_path / "suite.yaml"
    suite.write_text(
        "suite_id: profile_suite\n"
        "description: Profile suite.\n"
        "runs:\n"
        f"  - config: {config}\n"
        "    agent: agent-command\n",
        encoding="utf-8",
    )
    return suite


def test_profile_loading_is_typed_and_deterministic(tmp_path: Path) -> None:
    path = _write_profile(tmp_path)

    first = load_agent_profile(path)
    second = load_agent_profile(path)

    assert first == second
    assert first.id == "test-profile"
    assert first.command == ["python3", "{task_prompt}", "{repo_dir}"]
    assert first.model == "model-1"
    assert first.metadata == {"provider": "test", "retries": 1}


@pytest.mark.parametrize(
    "command,match",
    [
        ('["python3", "{unknown}"]', "Unknown"),
        ('["python3", "prompt={task_prompt}"]', "complete argv"),
    ],
)
def test_profile_rejects_unknown_or_embedded_placeholders(
    tmp_path: Path,
    command: str,
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        load_agent_profile(_write_profile(tmp_path, command=command))


def test_profile_rejects_secret_metadata_key(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    profile.write_text(
        profile.read_text(encoding="utf-8").replace(
            "  provider: test",
            "  api_key: committed-value",
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="secret-sensitive"):
        load_agent_profile(profile)


@pytest.mark.parametrize(
    "task",
    [
        "task: {}",
        'task:\n  prompt: "one"\n  prompt_file: prompt.txt',
    ],
)
def test_task_requires_exactly_one_prompt_source(
    tmp_path: Path,
    task: str,
) -> None:
    with pytest.raises(ValueError, match="exactly one"):
        load_config(_write_config(tmp_path, task=task))


def test_prompt_file_traversal_and_size_are_rejected(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-prompt.txt"
    outside.write_text("outside", encoding="utf-8")
    with pytest.raises(ValueError, match="within"):
        load_config(
            _write_config(
                tmp_path,
                task="task:\n  prompt_file: ../outside-prompt.txt",
            )
        )

    prompt = tmp_path / "large.txt"
    prompt.write_bytes(b"x" * (MAX_TASK_PROMPT_FILE_BYTES + 1))
    with pytest.raises(ValueError, match="byte limit"):
        load_config(
            _write_config(
                tmp_path,
                task="task:\n  prompt_file: large.txt",
            )
        )


def test_task_prompt_file_resolves_and_hashes(tmp_path: Path) -> None:
    prompt_file = tmp_path / "prompt.txt"
    prompt_file.write_text("File prompt.", encoding="utf-8")
    config = load_config(
        _write_config(tmp_path, task="task:\n  prompt_file: prompt.txt")
    )

    prompt = load_task_prompt(config)

    assert prompt.source == "file"
    assert prompt.prompt_file == prompt_file.resolve()
    assert len(prompt.sha256) == 64


def test_invocation_renders_supported_placeholders_without_substrings(
    tmp_path: Path,
) -> None:
    prompt_file = tmp_path / "prompt.txt"
    prompt_file.write_text("Prompt contents.", encoding="utf-8")
    profile = load_agent_profile(
        _write_profile(
            tmp_path,
            command='["python3", "{task_file}", "{repo_dir}"]',
        )
    )
    config = load_config(
        _write_config(tmp_path, task="task:\n  prompt_file: prompt.txt")
    )
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    rendered = render_invocation(profile, config, repo_dir)
    dry = dry_run_invocation(profile, config)

    assert Path(rendered.argv[0]).is_absolute()
    assert rendered.display_argv[0] == "python3"
    assert rendered.argv[1] == str(prompt_file.resolve())
    assert rendered.argv[2] == str(repo_dir.resolve())
    assert dry.display_argv[1].startswith("[TASK_FILE sha256:")
    assert dry.display_argv[2] == "[REPO_DIR]"


def test_task_file_placeholder_requires_file_source(tmp_path: Path) -> None:
    profile = load_agent_profile(
        _write_profile(tmp_path, command='["python3", "{task_file}"]')
    )
    config = load_config(_write_config(tmp_path))

    with pytest.raises(ValueError, match="requires task_file"):
        dry_run_invocation(profile, config)


def test_dry_run_sanitizes_credential_arguments(tmp_path: Path) -> None:
    profile = load_agent_profile(
        _write_profile(
            tmp_path,
            command='["python3", "--api-key", "committed-canary", "{task_prompt}"]',
        )
    )
    config = load_config(_write_config(tmp_path))

    rendered = dry_run_invocation(profile, config)

    assert "committed-canary" not in rendered.display_argv
    assert "[REDACTED]" in rendered.display_argv


def test_validation_detects_missing_executable_and_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _write_config(tmp_path)
    suite = _write_suite(tmp_path, config)
    missing_executable = _write_profile(
        tmp_path,
        executable="definitely-missing-agentguard-executable",
    )
    with pytest.raises(ValueError, match="executable"):
        build_evaluation_plan(missing_executable, suite)

    profile = _write_profile(
        tmp_path,
        environment="[AGENTGUARD_REQUIRED_SECRET]",
    )
    monkeypatch.delenv("AGENTGUARD_REQUIRED_SECRET", raising=False)
    with pytest.raises(ValueError, match="AGENTGUARD_REQUIRED_SECRET"):
        validate_evaluation(profile, suite)


def test_environment_allowlist_copies_only_requested_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = load_agent_profile(
        _write_profile(tmp_path, environment="[ALLOWED_VALUE]")
    )
    config = load_config(_write_config(tmp_path))
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    monkeypatch.setenv("ALLOWED_VALUE", "canary")
    monkeypatch.setenv("UNLISTED_VALUE", "must-not-pass")

    rendered = render_invocation(profile, config, repo_dir)

    assert rendered.environment == {"ALLOWED_VALUE": "canary"}
    assert "UNLISTED_VALUE" not in rendered.environment
    assert os.environ["UNLISTED_VALUE"] == "must-not-pass"


def test_profile_relative_executable_resolves_independently_of_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "profile-agent"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    profile = load_agent_profile(
        _write_profile(
            tmp_path,
            executable="./profile-agent",
        )
    )
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    monkeypatch.chdir(unrelated)

    resolved = resolve_profile_argv(profile, profile.command)

    assert resolved[0] == str(executable.resolve())
