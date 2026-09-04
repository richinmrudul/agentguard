import hashlib
import json
import re
import subprocess
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

import agentguard.project_init as project_init_module
from agentguard.cli.main import app
from agentguard.config.loader import load_config
from agentguard.project_init import (
    CONFIG_PATH,
    GO_TEST_COMMAND,
    GITHUB_WORKFLOW_PATH,
    MAX_GO_MOD_BYTES,
    MAX_NODE_PACKAGE_JSON_BYTES,
    MAX_PYTHON_METADATA_BYTES,
    NODE_TEST_COMMAND,
    PYTHON_REQUIREMENT_FILES,
    UNKNOWN_TEST_COMMAND,
)
from agentguard.presets import get_preset, preset_names


runner = CliRunner()
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
ANSI_STYLE = re.compile(r"\x1b\[[0-9;]*m")


def _error_output(result) -> str:
    try:
        return result.stderr
    except ValueError:
        return result.output


def _invoke(root: Path, *args: str):
    return runner.invoke(app, ["init", str(root), *args])


def _python_project(root: Path) -> None:
    root.mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        "[project]\nname = 'demo'\n\n[tool.pytest.ini_options]\ntestpaths = ['tests']\n",
        encoding="utf-8",
    )


def _node_project(
    root: Path,
    *,
    test_script: str = NODE_TEST_COMMAND,
    package_fields=None,
) -> None:
    root.mkdir(parents=True)
    package = {"name": "demo", "scripts": {"test": test_script}}
    package.update(package_fields or {})
    (root / "package.json").write_text(
        json.dumps(package, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _go_project(
    root: Path, *, module_path: str = "example.com/agentguard-fixture"
) -> None:
    root.mkdir(parents=True)
    (root / "go.mod").write_text(
        f"module {module_path}\n\ngo 1.26\n",
        encoding="utf-8",
    )


def _workflow(root: Path) -> dict:
    return yaml.safe_load((root / GITHUB_WORKFLOW_PATH).read_text(encoding="utf-8"))


def test_init_basic_python_project_generates_strict_valid_config(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _python_project(root)

    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0, result.output
    config = load_config(root / CONFIG_PATH)
    assert config.mode == "ci"
    assert config.test_command == "python -m pytest"
    assert "Detected project type: Python" in result.output
    assert not (root / GITHUB_WORKFLOW_PATH).exists()
    assert (root / ".gitignore").read_text(encoding="utf-8") == ".agentguard/\n"


def test_detected_pytest_workflow_installs_project_and_pytest(tmp_path: Path) -> None:
    root = tmp_path / "Python project café 日本語"
    _python_project(root)

    result = _invoke(root, "--ci", "github")
    steps = _workflow(root)["jobs"]["agentguard"]["steps"]
    setup = next(
        step for step in steps if step.get("name") == "Install detected Python test dependencies"
    )

    assert result.exit_code == 0, result.output
    assert setup["run"].splitlines() == [
        "python -m pip install --editable .",
        "python -m pip install pytest",
    ]


def test_build_system_only_pyproject_does_not_trigger_editable_install(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        "[build-system]\nrequires = ['setuptools']\n\n"
        "[tool.pytest.ini_options]\ntestpaths = ['tests']\n",
        encoding="utf-8",
    )

    result = _invoke(root, "--ci", "github")
    steps = _workflow(root)["jobs"]["agentguard"]["steps"]
    setup = next(
        step for step in steps if step.get("name") == "Install detected Python test dependencies"
    )

    assert result.exit_code == 0, result.output
    assert setup["run"].splitlines() == ["python -m pip install pytest"]


@pytest.mark.parametrize("requirements_name", PYTHON_REQUIREMENT_FILES)
def test_detected_pytest_workflow_installs_allowlisted_requirements_without_editable_mode(
    tmp_path: Path, requirements_name: str
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (root / requirements_name).write_text("example-dependency==1\n", encoding="utf-8")

    result = _invoke(root, "--ci", "github")
    steps = _workflow(root)["jobs"]["agentguard"]["steps"]
    setup = next(
        step for step in steps if step.get("name") == "Install detected Python test dependencies"
    )

    assert result.exit_code == 0, result.output
    assert setup["run"].splitlines() == [
        f"python -m pip install --requirement {requirements_name}",
        "python -m pip install pytest",
    ]
    assert "--editable" not in setup["run"]


def test_multiple_allowlisted_requirements_have_deterministic_fixed_order(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    for name in reversed(PYTHON_REQUIREMENT_FILES):
        (root / name).write_text("example-dependency==1\n", encoding="utf-8")

    result = _invoke(root, "--ci", "github")
    steps = _workflow(root)["jobs"]["agentguard"]["steps"]
    setup = next(
        step for step in steps if step.get("name") == "Install detected Python test dependencies"
    )

    assert result.exit_code == 0, result.output
    assert setup["run"].splitlines() == [
        *(f"python -m pip install --requirement {name}" for name in PYTHON_REQUIREMENT_FILES),
        "python -m pip install pytest",
    ]


@pytest.mark.parametrize(
    ("metadata_name", "metadata_source", "pytest_source"),
    [
        ("setup.cfg", "[metadata]\nname = demo\n\n[tool:pytest]\n", None),
        ("setup.py", "raise RuntimeError('must not run during init')\n", "[pytest]\n"),
        ("tox.ini", "[pytest]\n", None),
    ],
)
def test_python_setup_detection_is_inert_and_only_installs_packaged_roots_editably(
    tmp_path: Path,
    monkeypatch,
    metadata_name: str,
    metadata_source: str,
    pytest_source: str,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / metadata_name).write_text(metadata_source, encoding="utf-8")
    if pytest_source is not None:
        (root / "pytest.ini").write_text(pytest_source, encoding="utf-8")

    def fail(*args, **kwargs):
        raise AssertionError(f"initialization executed repository code: {args!r} {kwargs!r}")

    monkeypatch.setattr(subprocess, "run", fail)
    result = _invoke(root, "--ci", "github")
    workflow_source = (root / GITHUB_WORKFLOW_PATH).read_text(encoding="utf-8")

    assert result.exit_code == 0, result.output
    if metadata_name in {"setup.cfg", "setup.py"}:
        assert "python -m pip install --editable ." in workflow_source
    else:
        assert "--editable" not in workflow_source
    assert "python -m pip install pytest" in workflow_source


@pytest.mark.parametrize(
    "unsafe_name",
    ["requirements-prod.txt", "requirements.txt", "pyproject.toml", "setup.cfg", "setup.py"],
)
def test_unsafe_or_unrecognized_dependency_metadata_requires_customization(
    tmp_path: Path, unsafe_name: str
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.write_text("untrusted\n", encoding="utf-8")
    if unsafe_name == "requirements-prod.txt":
        (root / unsafe_name).write_text("untrusted\n", encoding="utf-8")
    else:
        (root / unsafe_name).symlink_to(outside)

    result = _invoke(root, "--ci", "github")
    source = (root / GITHUB_WORKFLOW_PATH).read_text(encoding="utf-8")

    assert result.exit_code == 0, result.output
    assert load_config(root / CONFIG_PATH).test_command == UNKNOWN_TEST_COMMAND
    assert "Install detected Python test dependencies" not in source


def test_oversized_python_dependency_metadata_requires_customization(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (root / "pyproject.toml").write_bytes(b" " * (MAX_PYTHON_METADATA_BYTES + 1))

    result = _invoke(root, "--ci", "github")

    assert result.exit_code == 0, result.output
    assert load_config(root / CONFIG_PATH).test_command == UNKNOWN_TEST_COMMAND


def test_explicit_command_does_not_guess_python_dependency_setup(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _python_project(root)

    result = _invoke(
        root, "--ci", "github", "--test-command", "python -m pytest tests/unit"
    )
    source = (root / GITHUB_WORKFLOW_PATH).read_text(encoding="utf-8")

    assert result.exit_code == 0, result.output
    assert "Install detected Python test dependencies" not in source


def test_default_is_byte_identical_to_explicit_recommended(tmp_path: Path) -> None:
    implicit = tmp_path / "implicit"
    explicit = tmp_path / "explicit"
    _python_project(implicit)
    _python_project(explicit)

    implicit_result = _invoke(implicit, "--no-ci")
    explicit_result = _invoke(explicit, "--no-ci", "--preset", "recommended")

    assert implicit_result.exit_code == explicit_result.exit_code == 0
    assert (implicit / CONFIG_PATH).read_bytes() == (explicit / CONFIG_PATH).read_bytes()
    assert hashlib.sha256((implicit / CONFIG_PATH).read_bytes()).hexdigest() == (
        "1f6ae85d14b383773cddfb46540947dd129bb6b0c68e860d001516fc5095dc84"
    )
    assert "Selected preset: recommended" in implicit_result.output


@pytest.mark.parametrize("preset_name", preset_names())
def test_every_preset_generates_configuration_accepted_by_production_loader(
    tmp_path: Path, preset_name: str
) -> None:
    root = tmp_path / preset_name
    _python_project(root)

    result = _invoke(root, "--no-ci", "--preset", preset_name)
    config = load_config(root / CONFIG_PATH)
    expected = get_preset(preset_name).settings

    assert result.exit_code == 0, result.output
    assert config.command_timeout_seconds == expected.command_timeout_seconds
    assert config.max_output_bytes == expected.max_output_bytes
    assert config.expected_modified_files.max == expected.expected_modified_files_max
    assert config.diff_limits.max_files_changed == expected.max_files_changed
    assert config.policy == dict(expected.policy_severities)
    assert config.secret_content_builtin_detectors == list(
        expected.secret_content_builtin_detectors
    )
    source = (root / CONFIG_PATH).read_text(encoding="utf-8")
    for unsupported in (
        "sandbox:",
        "docker:",
        "command_policy:",
        "filesystem_watcher:",
        "benchmark:",
    ):
        assert unsupported not in source


def test_explicit_test_command_is_preserved_as_one_yaml_value(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    command = "python -m pytest -k \"safe or quoted\"; echo $TOKEN && touch /tmp/no"

    result = _invoke(root, "--test-command", command, "--no-ci")

    assert result.exit_code == 0, result.output
    assert load_config(root / CONFIG_PATH).test_command == command
    assert command not in result.output
    assert "Test command: supplied with --test-command" in result.output


def test_unknown_project_uses_failing_customization_placeholder(tmp_path: Path) -> None:
    root = tmp_path / "empty"
    root.mkdir()

    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0
    assert load_config(root / CONFIG_PATH).test_command == UNKNOWN_TEST_COMMAND
    assert "No safe test command was detected" in (
        root / CONFIG_PATH
    ).read_text(encoding="utf-8")
    assert "Detected project type: unknown" in result.output


@pytest.mark.parametrize(
    ("lockfile", "manager"),
    [
        (None, None),
        ("package-lock.json", "npm"),
        ("npm-shrinkwrap.json", "npm"),
        ("yarn.lock", "yarn"),
        ("pnpm-lock.yaml", "pnpm"),
        ("bun.lock", "bun"),
        ("bun.lockb", "bun"),
    ],
)
def test_node_native_test_runner_is_detected_without_package_manager_execution(
    tmp_path: Path,
    monkeypatch,
    lockfile: str,
    manager: str,
) -> None:
    root = tmp_path / "node project café"
    fields = {"packageManager": f"{manager}@1.2.3"} if manager else None
    _node_project(root, package_fields=fields)
    if lockfile:
        (root / lockfile).write_bytes(b"untrusted lock metadata\n")

    def fail(*args, **kwargs):
        raise AssertionError(f"unexpected command execution: {args!r} {kwargs!r}")

    monkeypatch.setattr(subprocess, "run", fail)
    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0, result.output
    assert "Detected project type: Node.js" in result.output
    assert "detected Node.js test runner" in result.output
    assert load_config(root / CONFIG_PATH).test_command == NODE_TEST_COMMAND


def test_node_lifecycle_scripts_are_not_invoked_or_copied(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    lifecycle = "touch must-not-exist"
    _node_project(
        root,
        package_fields={
            "scripts": {
                "pretest": lifecycle,
                "test": NODE_TEST_COMMAND,
                "posttest": lifecycle,
            }
        },
    )

    result = _invoke(root, "--no-ci")
    config_source = (root / CONFIG_PATH).read_text(encoding="utf-8")

    assert result.exit_code == 0, result.output
    assert load_config(root / CONFIG_PATH).test_command == NODE_TEST_COMMAND
    assert lifecycle not in config_source
    assert not (root / "must-not-exist").exists()


def test_node_dry_run_is_byte_for_byte_inert(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _node_project(root)
    before = {path.relative_to(root): path.read_bytes() for path in root.rglob("*")}

    result = _invoke(root, "--dry-run", "--ci", "github")
    after = {path.relative_to(root): path.read_bytes() for path in root.rglob("*")}

    assert result.exit_code == 0, result.output
    assert before == after
    assert "Dry run complete" in result.output


@pytest.mark.parametrize(
    "test_script",
    [
        "npm test",
        "npm run test:unit",
        "node --test; touch owned",
        "node --test && npm run posttest",
        "yarn test",
        "pnpm test",
        "bun test",
        "vitest",
        "jest",
        "node --test ",
    ],
)
def test_node_package_scripts_are_not_guessed_or_copied(
    tmp_path: Path, test_script: str
) -> None:
    root = tmp_path / "repo"
    _node_project(root, test_script=test_script)

    result = _invoke(root, "--no-ci")
    config_source = (root / CONFIG_PATH).read_text(encoding="utf-8")

    assert result.exit_code == 0, result.output
    assert load_config(root / CONFIG_PATH).test_command == UNKNOWN_TEST_COMMAND
    assert test_script not in config_source


@pytest.mark.parametrize(
    "package_source",
    [
        "{not json}\n",
        "[]\n",
        '{"scripts":{},"scripts":{"test":"node --test"}}\n',
        '{"scripts":{"test":"node --test"},"value":NaN}\n',
    ],
)
def test_invalid_node_metadata_fails_closed_to_customization(
    tmp_path: Path, package_source: str
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "package.json").write_text(package_source, encoding="utf-8")

    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0, result.output
    assert "Detected project type: Node.js" in result.output
    assert load_config(root / CONFIG_PATH).test_command == UNKNOWN_TEST_COMMAND


def test_oversized_node_metadata_is_bounded_and_requires_customization(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "package.json").write_bytes(b" " * (MAX_NODE_PACKAGE_JSON_BYTES + 1))

    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0, result.output
    assert load_config(root / CONFIG_PATH).test_command == UNKNOWN_TEST_COMMAND


@pytest.mark.parametrize(
    "mutate",
    [
        "workspace",
        "multiple-lockfiles",
        "manager-mismatch",
        "mixed-python-node",
    ],
)
def test_ambiguous_node_projects_require_explicit_customization(
    tmp_path: Path, mutate: str
) -> None:
    root = tmp_path / "repo"
    fields = {"workspaces": ["packages/*"]} if mutate == "workspace" else None
    _node_project(root, package_fields=fields)
    if mutate == "multiple-lockfiles":
        (root / "package-lock.json").write_text("{}\n", encoding="utf-8")
        (root / "yarn.lock").write_text("untrusted\n", encoding="utf-8")
    elif mutate == "manager-mismatch":
        package = json.loads((root / "package.json").read_text(encoding="utf-8"))
        package["packageManager"] = "pnpm@10.0.0"
        (root / "package.json").write_text(json.dumps(package), encoding="utf-8")
        (root / "package-lock.json").write_text("{}\n", encoding="utf-8")
    elif mutate == "mixed-python-node":
        (root / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")

    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0, result.output
    assert load_config(root / CONFIG_PATH).test_command == UNKNOWN_TEST_COMMAND
    assert "requires customization" in result.output


def test_explicit_test_command_precedes_ambiguous_node_detection(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _node_project(root, package_fields={"workspaces": ["packages/*"]})
    explicit = "node --test test/safe.test.js"

    result = _invoke(root, "--no-ci", "--test-command", explicit)

    assert result.exit_code == 0, result.output
    assert load_config(root / CONFIG_PATH).test_command == explicit
    assert "Test command: supplied with --test-command" in result.output


def test_node_workflow_is_pinned_least_privilege_and_never_installs_dependencies(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    _node_project(root)

    result = _invoke(root, "--ci", "github")
    source = (root / GITHUB_WORKFLOW_PATH).read_text(encoding="utf-8")
    workflow = _workflow(root)
    steps = workflow["jobs"]["agentguard"]["steps"]

    assert result.exit_code == 0, result.output
    assert workflow["permissions"] == {"contents": "read"}
    assert "pull_request_target" not in source
    assert any(
        step.get("uses")
        == "actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38"
        and step.get("with") == {"node-version": "24"}
        for step in steps
    )
    assert not any(
        token in source
        for token in (
            "npm install",
            "npm ci",
            "npm test",
            "yarn ",
            "pnpm ",
            "bun ",
        )
    )
    assert "secrets." not in source
    assert "id-token" not in source


def test_node_package_symlink_is_not_followed_for_detection(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    outside = tmp_path / "outside-package.json"
    root.mkdir()
    outside.write_text(
        '{"scripts":{"test":"node --test"}}\n', encoding="utf-8"
    )
    (root / "package.json").symlink_to(outside)

    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0, result.output
    assert "Detected project type: unknown" in result.output
    assert load_config(root / CONFIG_PATH).test_command == UNKNOWN_TEST_COMMAND


def test_go_module_is_detected_without_executing_go_or_reading_go_sum(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "Go project café 日本語"
    _go_project(root)
    (root / "go.sum").write_bytes(b"untrusted module checksum metadata\x00\xff\n")

    def fail(*args, **kwargs):
        raise AssertionError(f"unexpected command execution: {args!r} {kwargs!r}")

    monkeypatch.setattr(subprocess, "run", fail)
    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0, result.output
    assert "Detected project type: Go" in result.output
    assert "detected Go module" in result.output
    assert load_config(root / CONFIG_PATH).test_command == GO_TEST_COMMAND
    assert "untrusted module checksum" not in (root / CONFIG_PATH).read_text(
        encoding="utf-8"
    )


@pytest.mark.parametrize(
    "go_mod",
    [
        b"",
        b"go 1.26\n",
        b"module example.com/one\nmodule example.com/two\n",
        b"module example.com/valid\nmodule\n",
        b'module "example.com/quoted"\n',
        b"module ../outside\n",
        b"module example.com/../outside\n",
        b"/*\nmodule example.com/commented\n*/\n",
        b"module example.com/demo\x00\n",
        b"module example.com/demo\xff\n",
    ],
)
def test_invalid_go_module_directive_requires_customization(
    tmp_path: Path, go_mod: bytes
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "go.mod").write_bytes(go_mod)

    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0, result.output
    assert "Detected project type: Go" in result.output
    assert load_config(root / CONFIG_PATH).test_command == UNKNOWN_TEST_COMMAND


def test_non_module_go_mod_content_remains_opaque_untrusted_data(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "Go project café"
    root.mkdir()
    unsafe_payload = "touch must-not-exist && curl https://attacker.invalid"
    (root / "go.mod").write_text(
        "module example.com/agentguard-fixture\n\n"
        "go 1.26\n\n"
        "require (\n"
        "    example.com/dependency v1.2.3\n"
        ")\n\n"
        "replace example.com/dependency => ./local-dependency\n"
        f"// opaque untrusted value: {unsafe_payload}\n",
        encoding="utf-8",
    )

    def fail(*args, **kwargs):
        raise AssertionError(f"unexpected command execution: {args!r} {kwargs!r}")

    monkeypatch.setattr(subprocess, "run", fail)
    result = _invoke(root, "--ci", "github")
    config_source = (root / CONFIG_PATH).read_text(encoding="utf-8")
    workflow_source = (root / GITHUB_WORKFLOW_PATH).read_text(encoding="utf-8")

    assert result.exit_code == 0, result.output
    assert load_config(root / CONFIG_PATH).test_command == GO_TEST_COMMAND
    assert unsafe_payload not in config_source
    assert unsafe_payload not in workflow_source
    assert "example.com/dependency" not in config_source
    assert "example.com/dependency" not in workflow_source


def test_oversized_go_metadata_is_bounded_and_requires_customization(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "go.mod").write_bytes(b" " * (MAX_GO_MOD_BYTES + 1))

    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0, result.output
    assert load_config(root / CONFIG_PATH).test_command == UNKNOWN_TEST_COMMAND


@pytest.mark.parametrize("ambiguity", ["workspace", "python", "node", "go-sum-only"])
def test_ambiguous_go_projects_require_explicit_customization(
    tmp_path: Path, ambiguity: str
) -> None:
    root = tmp_path / "repo"
    if ambiguity == "go-sum-only":
        root.mkdir()
        (root / "go.sum").write_text("untrusted\n", encoding="utf-8")
    else:
        _go_project(root)
        if ambiguity == "workspace":
            (root / "go.work").write_text("go 1.26\nuse ./module\n", encoding="utf-8")
        elif ambiguity == "python":
            (root / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
        elif ambiguity == "node":
            (root / "package.json").write_text(
                '{"scripts":{"test":"node --test"}}\n', encoding="utf-8"
            )

    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0, result.output
    assert load_config(root / CONFIG_PATH).test_command == UNKNOWN_TEST_COMMAND
    assert "requires customization" in result.output


def test_explicit_test_command_precedes_ambiguous_go_detection(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _go_project(root)
    (root / "go.work").write_text("use ./module\n", encoding="utf-8")
    explicit = "go test ./internal/safe"

    result = _invoke(root, "--no-ci", "--test-command", explicit)

    assert result.exit_code == 0, result.output
    assert load_config(root / CONFIG_PATH).test_command == explicit
    assert "Test command: supplied with --test-command" in result.output


def test_go_workflow_is_pinned_least_privilege_and_does_not_download_modules(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    _go_project(root)

    result = _invoke(root, "--ci", "github")
    source = (root / GITHUB_WORKFLOW_PATH).read_text(encoding="utf-8")
    workflow = _workflow(root)
    steps = workflow["jobs"]["agentguard"]["steps"]

    assert result.exit_code == 0, result.output
    assert workflow["permissions"] == {"contents": "read"}
    assert "pull_request_target" not in source
    assert any(
        step.get("uses") == "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e"
        and step.get("with") == {"go-version": "1.26.x", "cache": "false"}
        for step in steps
    )
    assert not any(
        token in source
        for token in ("go test", "go list", "go env", "go generate", "go get", "go mod")
    )
    assert "secrets." not in source
    assert "id-token" not in source


@pytest.mark.parametrize("metadata_name", ["go.mod", "go.work", "go.sum"])
def test_go_metadata_symlinks_are_not_followed_for_detection(
    tmp_path: Path, metadata_name: str
) -> None:
    root = tmp_path / "repo"
    if metadata_name == "go.mod":
        root.mkdir()
    else:
        _go_project(root)
    outside = tmp_path / f"outside-{metadata_name}"
    outside.write_text("module example.com/outside\n", encoding="utf-8")
    (root / metadata_name).symlink_to(outside)

    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0, result.output
    if metadata_name == "go.mod":
        assert "Detected project type: unknown" in result.output
    else:
        assert "Detected project type: Go" in result.output
    assert load_config(root / CONFIG_PATH).test_command == UNKNOWN_TEST_COMMAND


def test_go_dry_run_and_idempotent_apply_preserve_project_files(tmp_path: Path) -> None:
    dry_root = tmp_path / "dry Go café"
    _go_project(dry_root)
    before = {
        path.relative_to(dry_root): path.read_bytes() for path in dry_root.rglob("*")
    }

    dry = _invoke(dry_root, "--dry-run", "--ci", "github")
    after = {
        path.relative_to(dry_root): path.read_bytes() for path in dry_root.rglob("*")
    }

    assert dry.exit_code == 0, dry.output
    assert before == after

    root = tmp_path / "applied Go 日本語"
    _go_project(root)
    first = _invoke(root, "--ci", "github")
    applied = {
        path.relative_to(root): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }
    second = _invoke(root, "--ci", "github")
    repeated = {
        path.relative_to(root): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }

    assert first.exit_code == second.exit_code == 0
    assert applied == repeated
    assert "Already current:" in second.output


@pytest.mark.parametrize("preset_name", preset_names())
def test_github_workflow_is_valid_least_privilege_and_pinned(
    tmp_path: Path, preset_name: str
) -> None:
    root = tmp_path / "repo"
    _python_project(root)

    result = _invoke(root, "--ci", "github", "--preset", preset_name)

    assert result.exit_code == 0, result.output
    workflow = _workflow(root)
    assert workflow["permissions"] == {"contents": "read"}
    assert "pull_request_target" not in workflow
    assert "pull_request" in workflow.get("on", workflow.get(True))
    steps = workflow["jobs"]["agentguard"]["steps"]
    uses = [step["uses"] for step in steps if "uses" in step]
    assert uses
    assert all(FULL_SHA.fullmatch(item.rsplit("@", 1)[1]) for item in uses)
    source = (root / GITHUB_WORKFLOW_PATH).read_text(encoding="utf-8")
    assert "agentguard-evals==0.3.1" in source
    assert "agentguard ci --config agentguard.yaml" in source
    assert "--base \"$AGENTGUARD_BASE_SHA\" --head HEAD --github-summary" in source
    assert "secrets." not in source
    assert "id-token" not in source
    setup = next(
        step for step in steps if step.get("name") == "Install detected Python test dependencies"
    )
    assert setup["run"].splitlines() == [
        "python -m pip install --editable .",
        "python -m pip install pytest",
    ]


def test_no_ci_does_not_generate_workflow(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()

    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0
    assert not (root / GITHUB_WORKFLOW_PATH).exists()
    assert "rerun with --ci github" in result.output


def test_dry_run_leaves_project_byte_for_byte_unchanged(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    existing = root / "keep.txt"
    existing.write_bytes(b"\x00original\n")
    before = {path.relative_to(root): path.read_bytes() for path in root.rglob("*")}

    result = _invoke(root, "--dry-run", "--ci", "github")

    after = {path.relative_to(root): path.read_bytes() for path in root.rglob("*")}
    assert result.exit_code == 0, result.output
    assert before == after
    assert "Would create:" in result.output
    assert "Dry run complete" in result.output


def test_default_refuses_nonidentical_existing_config_without_partial_writes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    config = root / CONFIG_PATH
    config.write_text("user: config\n", encoding="utf-8")

    result = _invoke(root, "--ci", "github")

    assert result.exit_code == 1
    assert config.read_text(encoding="utf-8") == "user: config\n"
    assert not (root / ".gitignore").exists()
    assert not (root / GITHUB_WORKFLOW_PATH).exists()
    assert "Conflict:\n- agentguard.yaml" in result.output


@pytest.mark.parametrize(
    "failed_target",
    [CONFIG_PATH, Path(".gitignore"), GITHUB_WORKFLOW_PATH],
)
def test_write_failure_at_each_stage_rolls_back_every_initializer_target(
    tmp_path: Path,
    monkeypatch,
    failed_target: Path,
) -> None:
    root = tmp_path / "project with spaces café 日本語"
    root.mkdir()
    original_write = project_init_module.atomic_write_text
    failed = False

    def fail_after_write(path: Path, content: str, **kwargs):
        nonlocal failed
        result = original_write(path, content, **kwargs)
        if path.relative_to(root) == failed_target and not failed:
            failed = True
            raise OSError("hostile private failure detail")
        return result

    monkeypatch.setattr(project_init_module, "atomic_write_text", fail_after_write)

    result = _invoke(root, "--ci", "github")

    assert result.exit_code == 2
    assert "all earlier changes were rolled back" in _error_output(result)
    assert "hostile private failure detail" not in result.output
    assert str(tmp_path) not in result.output
    assert not (root / CONFIG_PATH).exists()
    assert not (root / ".gitignore").exists()
    assert not (root / GITHUB_WORKFLOW_PATH).exists()
    assert not (root / ".github").exists()
    assert not list(root.glob(".*.agentguard-rollback-*.bak"))


def test_later_write_failure_restores_preexisting_gitignore_byte_for_byte(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    ignore = root / ".gitignore"
    original = b"dist/\r\ncustom-caf\xc3\xa9/\r\n"
    ignore.write_bytes(original)
    original_write = project_init_module.atomic_write_text

    def fail_workflow(path: Path, content: str, **kwargs):
        if path.relative_to(root) == GITHUB_WORKFLOW_PATH:
            raise PermissionError("private storage path")
        return original_write(path, content, **kwargs)

    monkeypatch.setattr(project_init_module, "atomic_write_text", fail_workflow)

    result = _invoke(root, "--ci", "github")

    assert result.exit_code == 2
    assert ignore.read_bytes() == original
    assert not (root / CONFIG_PATH).exists()
    assert not (root / GITHUB_WORKFLOW_PATH).exists()
    assert "private storage path" not in result.output
    assert not list(root.glob(".*.agentguard-rollback-*.bak"))


def test_force_replacement_is_restored_when_later_write_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    config = root / CONFIG_PATH
    config_original = b"user: config\r\n"
    config.write_bytes(config_original)
    original_write = project_init_module.atomic_write_text

    def fail_workflow(path: Path, content: str, **kwargs):
        if path.relative_to(root) == GITHUB_WORKFLOW_PATH:
            raise OSError("write refused")
        return original_write(path, content, **kwargs)

    monkeypatch.setattr(project_init_module, "atomic_write_text", fail_workflow)

    result = _invoke(root, "--force", "--ci", "github")

    assert result.exit_code == 2
    assert config.read_bytes() == config_original
    assert not (root / ".gitignore").exists()
    assert not (root / GITHUB_WORKFLOW_PATH).exists()


def test_rollback_failure_preserves_recoverable_backup_and_reports_target(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    ignore = root / ".gitignore"
    original = b"keep-this-user-content/\n"
    ignore.write_bytes(original)
    original_write = project_init_module.atomic_write_text
    workflow_failed = False

    def fail_write_and_restore(path: Path, content: str, **kwargs):
        nonlocal workflow_failed
        relative = path.relative_to(root)
        if relative == GITHUB_WORKFLOW_PATH:
            workflow_failed = True
            raise OSError("workflow failure")
        if relative == Path(".gitignore") and workflow_failed:
            raise OSError("rollback failure")
        return original_write(path, content, **kwargs)

    monkeypatch.setattr(
        project_init_module,
        "atomic_write_text",
        fail_write_and_restore,
    )

    result = _invoke(root, "--ci", "github")
    backups = list(root.glob("..gitignore.agentguard-rollback-*.bak"))

    assert result.exit_code == 2
    assert "rollback was incomplete for .gitignore" in _error_output(result)
    assert "recovery backups were preserved" in _error_output(result)
    assert "workflow failure" not in result.output
    assert "rollback failure" not in result.output
    assert ignore.read_bytes().endswith(b".agentguard/\n")
    assert len(backups) == 1
    assert backups[0].read_bytes() == original
    assert not (root / CONFIG_PATH).exists()
    assert not (root / GITHUB_WORKFLOW_PATH).exists()


def test_force_replaces_only_owned_targets(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / CONFIG_PATH).write_text("user: config\n", encoding="utf-8")
    workflow = root / GITHUB_WORKFLOW_PATH
    workflow.parent.mkdir(parents=True)
    workflow.write_text("name: user workflow\n", encoding="utf-8")
    unrelated = root / ".github/workflows/build.yml"
    unrelated.write_text("name: keep me\n", encoding="utf-8")
    readme = root / "README.md"
    readme.write_text("keep me\n", encoding="utf-8")

    result = _invoke(root, "--force", "--ci", "github", "--test-command", "pytest")

    assert result.exit_code == 0, result.output
    assert load_config(root / CONFIG_PATH).test_command == "pytest"
    assert "agentguard-evals==0.3.1" in workflow.read_text(encoding="utf-8")
    assert unrelated.read_text(encoding="utf-8") == "name: keep me\n"
    assert readme.read_text(encoding="utf-8") == "keep me\n"


def test_identical_rerun_is_idempotent(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _python_project(root)
    first = _invoke(root, "--ci", "github")
    before = {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}

    second = _invoke(root, "--ci", "github")

    after = {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}
    assert first.exit_code == second.exit_code == 0
    assert before == after
    assert "Already current:" in second.output


def test_switching_presets_conflicts_then_force_replaces_only_config(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    _python_project(root)
    keep = root / "keep.txt"
    keep.write_text("unchanged\n", encoding="utf-8")
    first = _invoke(root, "--ci", "github", "--preset", "minimal")
    workflow_before = (root / GITHUB_WORKFLOW_PATH).read_bytes()
    ignore_before = (root / ".gitignore").read_bytes()

    conflict = _invoke(root, "--ci", "github", "--preset", "strict")
    after_conflict = load_config(root / CONFIG_PATH)
    forced = _invoke(root, "--ci", "github", "--preset", "strict", "--force")
    after_force = load_config(root / CONFIG_PATH)

    assert first.exit_code == 0
    assert conflict.exit_code == 1
    assert after_conflict.expected_modified_files.max == 100
    assert forced.exit_code == 0, forced.output
    assert after_force.expected_modified_files.max == 25
    assert (root / GITHUB_WORKFLOW_PATH).read_bytes() == workflow_before
    assert (root / ".gitignore").read_bytes() == ignore_before
    assert keep.read_text(encoding="utf-8") == "unchanged\n"
    assert "Already current:\n- .gitignore\n- .github/workflows/agentguard.yml" in forced.output


@pytest.mark.parametrize("preset_name", preset_names())
def test_dry_run_for_each_preset_writes_nothing(
    tmp_path: Path, preset_name: str
) -> None:
    root = tmp_path / preset_name
    root.mkdir()

    result = _invoke(root, "--dry-run", "--ci", "github", "--preset", preset_name)

    assert result.exit_code == 0, result.output
    assert list(root.iterdir()) == []
    assert f"Selected preset: {preset_name}" in result.output


def test_gitignore_is_preserved_and_entry_is_deduplicated(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    ignore = root / ".gitignore"
    ignore.write_text("dist/\n.agentguard/\ncustom/\n", encoding="utf-8")

    first = _invoke(root, "--no-ci")
    second = _invoke(root, "--no-ci")

    assert first.exit_code == second.exit_code == 0
    assert ignore.read_text(encoding="utf-8") == "dist/\n.agentguard/\ncustom/\n"
    assert ignore.read_text(encoding="utf-8").count(".agentguard/") == 1


def test_gitignore_addition_preserves_unrelated_content_without_force(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    ignore = root / ".gitignore"
    ignore.write_text("dist/\ncustom/\n", encoding="utf-8")

    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0, result.output
    assert ignore.read_text(encoding="utf-8") == "dist/\ncustom/\n.agentguard/\n"
    assert "Updated:\n- .gitignore" in result.output


def test_existing_user_workflow_is_not_overwritten_without_force(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    workflow = root / GITHUB_WORKFLOW_PATH
    workflow.parent.mkdir(parents=True)
    workflow.write_text("name: custom\n", encoding="utf-8")

    result = _invoke(root, "--ci", "github")

    assert result.exit_code == 1
    assert workflow.read_text(encoding="utf-8") == "name: custom\n"


def test_symlink_escape_is_rejected_without_writing_outside(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / ".github").symlink_to(outside, target_is_directory=True)

    result = _invoke(root, "--ci", "github", "--force")

    assert result.exit_code == 2
    assert "escapes project root" in result.output
    assert not (outside / "workflows/agentguard.yml").exists()
    assert not (root / CONFIG_PATH).exists()


def test_dangling_parent_symlink_is_rejected_without_partial_writes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".github").symlink_to(tmp_path / "missing", target_is_directory=True)

    result = _invoke(root, "--ci", "github", "--force")

    assert result.exit_code == 2
    assert "unsafe parent symlink" in result.output
    assert not (root / CONFIG_PATH).exists()


def test_escaping_symlink_file_is_rejected_even_with_force(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text("keep\n", encoding="utf-8")
    (root / CONFIG_PATH).symlink_to(outside)

    result = _invoke(root, "--force", "--no-ci")

    assert result.exit_code == 2
    assert outside.read_text(encoding="utf-8") == "keep\n"


def test_detection_does_not_follow_project_signal_symlink_outside_root(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside-pyproject.toml"
    outside.write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
    (root / "pyproject.toml").symlink_to(outside)

    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0, result.output
    assert "Detected project type: unknown" in result.output
    assert load_config(root / CONFIG_PATH).test_command == UNKNOWN_TEST_COMMAND


def test_spaces_unicode_and_parent_directory_path_work(tmp_path: Path, monkeypatch) -> None:
    parent = tmp_path / "parent"
    root = parent / "space café 日本語"
    parent.mkdir()
    root.mkdir()
    monkeypatch.chdir(parent)

    result = runner.invoke(app, ["init", root.name, "--no-ci", "--test-command", "pytest"])

    assert result.exit_code == 0, result.output
    assert (root / CONFIG_PATH).exists()
    assert root.name in result.output


def test_init_from_target_directory_uses_current_directory(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.chdir(root)

    result = runner.invoke(app, ["init", "--no-ci", "--test-command", "pytest"])

    assert result.exit_code == 0, result.output
    assert (root / CONFIG_PATH).exists()
    assert "Initialized AgentGuard in ." in result.output


def test_detection_never_executes_repository_commands(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "repo"
    _python_project(root)
    (root / "setup.py").write_text("raise SystemExit('must not execute')\n", encoding="utf-8")

    def fail(*args, **kwargs):
        raise AssertionError(f"unexpected command execution: {args!r} {kwargs!r}")

    monkeypatch.setattr(subprocess, "run", fail)

    result = _invoke(root, "--dry-run", "--ci", "github")

    assert result.exit_code == 0, result.output


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("--ci", "gitlab"), "supports only 'github'"),
        (("--ci", "github", "--no-ci"), "cannot be used together"),
        (("--test-command", "   "), "non-empty"),
    ],
)
def test_invalid_options_have_concise_errors_without_tracebacks(
    tmp_path: Path,
    args: tuple[str, ...],
    message: str,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()

    result = _invoke(root, *args)

    assert result.exit_code == 2
    assert message in result.output
    assert "Traceback" not in result.output


def test_help_documents_final_interface() -> None:
    result = runner.invoke(app, ["init", "--help"])

    assert result.exit_code == 0
    help_text = ANSI_STYLE.sub("", result.output)
    assert "path" in help_text.lower()
    for option in ("--dry-run", "--force", "--ci", "--no-ci", "--test-command", "--preset"):
        assert option in help_text
    for name in preset_names():
        assert name in help_text


def test_unknown_preset_has_valid_choices_and_no_traceback(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()

    result = runner.invoke(
        app, ["init", str(root), "--preset", "Recommended", "--no-ci"]
    )

    assert result.exit_code == 2
    assert "Valid presets: minimal, recommended, strict" in _error_output(result)
    assert "Traceback" not in result.output
    assert list(root.iterdir()) == []
