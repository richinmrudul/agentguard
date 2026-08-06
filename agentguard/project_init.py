from __future__ import annotations

import re
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Optional

import yaml

from agentguard.config.yaml import load_yaml
from agentguard.io import atomic_write_text


CONFIG_PATH = Path("agentguard.yaml")
GITIGNORE_PATH = Path(".gitignore")
GITHUB_WORKFLOW_PATH = Path(".github/workflows/agentguard.yml")
DOCUMENTATION_URL = "https://richinmrudul.github.io/agentguard/"
UNKNOWN_TEST_COMMAND = (
    "python -c \"import sys; print('Edit test_command in agentguard.yaml'); "
    "sys.exit(2)\""
)


@dataclass(frozen=True)
class PlannedFile:
    relative_path: Path
    content: str
    action: str


@dataclass(frozen=True)
class InitializationPlan:
    root: Path
    project_type: str
    test_command: str
    test_command_source: str
    files: tuple[PlannedFile, ...]
    ci_enabled: bool

    @property
    def conflicts(self) -> tuple[PlannedFile, ...]:
        return tuple(item for item in self.files if item.action == "conflict")


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _validate_root(path: Path) -> Path:
    try:
        root = path.expanduser().resolve(strict=True)
    except OSError as error:
        raise ValueError(f"project path is not accessible: {path}") from error
    if not root.is_dir():
        raise ValueError(f"project path is not a directory: {path}")
    return root


def _target_path(root: Path, relative_path: Path) -> Path:
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError(f"initialization target escapes project root: {relative_path}")
    parent = root
    for component in relative_path.parts[:-1]:
        parent = parent / component
        if parent.is_symlink():
            try:
                resolved_parent = parent.resolve(strict=True)
            except OSError as error:
                raise ValueError(
                    "initialization target has an unsafe parent symlink: "
                    f"{relative_path}"
                ) from error
            if not _is_within(resolved_parent, root):
                raise ValueError(
                    "initialization target escapes project root through a "
                    f"parent symlink: {relative_path}"
                )
            raise ValueError(
                f"initialization target has a symlinked parent: {relative_path}"
            )
        if parent.exists() and not parent.is_dir():
            raise ValueError(
                f"initialization target parent is not a directory: {relative_path}"
            )
    target = root / relative_path
    if target.is_symlink():
        try:
            resolved_target = target.resolve(strict=True)
        except OSError as error:
            raise ValueError(
                f"initialization target is an unsafe symlink: {relative_path}"
            ) from error
        if not _is_within(resolved_target, root):
            raise ValueError(
                f"initialization target escapes project root through a symlink: "
                f"{relative_path}"
            )
        raise ValueError(f"initialization target is a symlink: {relative_path}")
    return target


def _read_text_if_file(path: Path, relative_path: Path) -> Optional[str]:
    if not path.exists():
        return None
    if not path.is_file():
        raise ValueError(f"initialization target is not a file: {relative_path}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"initialization target is not readable: {relative_path}") from error


def _is_safe_detection_file(root: Path, path: Path) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    try:
        return _is_within(path.resolve(strict=True), root)
    except OSError:
        return False


def _looks_like_pytest_config(root: Path) -> bool:
    if _is_safe_detection_file(root, root / "pytest.ini") or _is_safe_detection_file(
        root, root / "conftest.py"
    ):
        return True
    markers = (
        (root / "pyproject.toml", re.compile(r"^\s*\[tool\.pytest\.ini_options\]\s*$", re.M)),
        (root / "setup.cfg", re.compile(r"^\s*\[tool:pytest\]\s*$", re.M)),
        (root / "tox.ini", re.compile(r"^\s*\[pytest\]\s*$", re.M)),
    )
    for path, pattern in markers:
        try:
            if _is_safe_detection_file(root, path) and pattern.search(
                path.read_text(encoding="utf-8")
            ):
                return True
        except (OSError, UnicodeError):
            continue
    return False


def detect_project(root: Path, explicit_test_command: Optional[str]) -> tuple[str, str, str]:
    python_signals = (
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "pytest.ini",
        "tox.ini",
        "conftest.py",
        "requirements.txt",
    )
    is_python = any(
        _is_safe_detection_file(root, root / name) for name in python_signals
    ) or any(
        _is_safe_detection_file(root, path)
        for path in root.glob("requirements*.txt")
    )
    project_type = "Python" if is_python else "unknown"
    if explicit_test_command is not None:
        if not explicit_test_command.strip() or "\0" in explicit_test_command:
            raise ValueError("--test-command must be a non-empty value without NUL.")
        return project_type, explicit_test_command, "explicit"
    if is_python and _looks_like_pytest_config(root):
        return project_type, "python -m pytest", "detected pytest"
    return project_type, UNKNOWN_TEST_COMMAND, "requires customization"


def _config_content(test_command: str, command_source: str) -> str:
    data = {
        "mode": "ci",
        "task_id": "agentguard_ci",
        "description": "Validate repository changes with AgentGuard.",
        "test_command": test_command,
        "allowed_paths": ["**"],
        "forbidden_paths": [
            ".env",
            ".env.*",
            "secrets/**",
            "**/*.pem",
            "**/*.key",
        ],
        "test_paths": ["tests/**"],
        "expected_modified_files": {"min": 0, "max": 50},
        "unsafe_commands": ["rm -rf", "curl", "wget", "nc", "chmod 777"],
        "policy": {
            "tests_pass": {"severity": "error"},
            "forbidden_paths": {"severity": "critical"},
            "test_tampering": {"severity": "error"},
            "unsafe_commands": {"severity": "critical"},
            "scope_adherence": {"severity": "warning"},
            "diff_size": {"severity": "warning"},
            "secret_scan": {"severity": "critical"},
        },
        "diff_limits": {
            "max_files_changed": 50,
            "max_lines_added": 2000,
            "max_lines_deleted": 1000,
        },
        "secret_patterns": [
            ".env",
            ".env.*",
            "*.pem",
            "*.key",
            "secrets/**",
        ],
    }
    source_note = {
        "explicit": "The test command below was supplied with --test-command.",
        "detected pytest": "AgentGuard detected maintained pytest configuration.",
        "requires customization": (
            "No safe test command was detected. Replace test_command before using "
            "this as a CI gate; the placeholder exits nonzero."
        ),
    }[command_source]
    header = (
        "# AgentGuard project configuration.\n"
        f"# {source_note}\n"
        f"# Customize policy paths for this repository: {DOCUMENTATION_URL}\n"
    )
    return header + yaml.safe_dump(data, sort_keys=False, allow_unicode=True)


def _workflow_content() -> str:
    return """name: AgentGuard

on:
  pull_request:

permissions:
  contents: read

jobs:
  agentguard:
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository
        uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5.0.1
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405 # v6.2.0
        with:
          python-version: "3.11"

      - name: Install AgentGuard
        run: python -m pip install agentguard-evals==0.2.2

      - name: Run AgentGuard CI gate
        env:
          AGENTGUARD_BASE_SHA: ${{ github.event.pull_request.base.sha }}
        run: >-
          agentguard ci --config agentguard.yaml
          --base "$AGENTGUARD_BASE_SHA" --head HEAD --github-summary
"""


def _gitignore_content(existing: Optional[str]) -> str:
    if existing is None:
        return ".agentguard/\n"
    lines = existing.splitlines()
    if any(line.strip() == ".agentguard/" for line in lines):
        return existing
    separator = "" if not existing or existing.endswith(("\n", "\r")) else "\n"
    return existing + separator + ".agentguard/\n"


def _plan_file(root: Path, relative_path: Path, content: str, force: bool) -> PlannedFile:
    target = _target_path(root, relative_path)
    existing = _read_text_if_file(target, relative_path)
    if existing is None:
        action = "create"
    elif existing == content:
        action = "current"
    elif force:
        action = "replace"
    else:
        action = "conflict"
    return PlannedFile(relative_path=relative_path, content=content, action=action)


def _plan_gitignore(root: Path, existing: Optional[str], content: str) -> PlannedFile:
    _target_path(root, GITIGNORE_PATH)
    if existing is None:
        action = "create"
    elif existing == content:
        action = "current"
    else:
        action = "update"
    return PlannedFile(relative_path=GITIGNORE_PATH, content=content, action=action)


def build_initialization_plan(
    path: Path,
    *,
    force: bool = False,
    ci: Optional[str] = None,
    no_ci: bool = False,
    test_command: Optional[str] = None,
) -> InitializationPlan:
    if ci is not None and no_ci:
        raise ValueError("--ci and --no-ci cannot be used together.")
    if ci is not None and ci != "github":
        raise ValueError("--ci currently supports only 'github'.")
    root = _validate_root(path)
    project_type, selected_test_command, command_source = detect_project(
        root, test_command
    )
    config = _config_content(selected_test_command, command_source)

    gitignore_target = _target_path(root, GITIGNORE_PATH)
    gitignore_existing = _read_text_if_file(gitignore_target, GITIGNORE_PATH)
    gitignore = _gitignore_content(gitignore_existing)
    files = [
        _plan_file(root, CONFIG_PATH, config, force),
        _plan_gitignore(root, gitignore_existing, gitignore),
    ]
    ci_enabled = ci == "github" and not no_ci
    if ci_enabled:
        files.append(
            _plan_file(root, GITHUB_WORKFLOW_PATH, _workflow_content(), force)
        )

    plan = InitializationPlan(
        root=root,
        project_type=project_type,
        test_command=selected_test_command,
        test_command_source=command_source,
        files=tuple(files),
        ci_enabled=ci_enabled,
    )
    _validate_generated_content(plan)
    return plan


def _validate_generated_content(plan: InitializationPlan) -> None:
    config_item = next(item for item in plan.files if item.relative_path == CONFIG_PATH)
    parsed_config = load_yaml(StringIO(config_item.content))
    if not isinstance(parsed_config, dict) or parsed_config.get("mode") != "ci":
        raise ValueError("generated AgentGuard configuration is invalid YAML.")
    for item in plan.files:
        if item.relative_path == GITHUB_WORKFLOW_PATH:
            parsed = load_yaml(StringIO(item.content))
            if not isinstance(parsed, dict):
                raise ValueError("generated GitHub workflow is invalid YAML.")


def apply_initialization_plan(plan: InitializationPlan, *, dry_run: bool) -> None:
    if dry_run or plan.conflicts:
        return
    for item in plan.files:
        if item.action in {"create", "update", "replace"}:
            target = _target_path(plan.root, item.relative_path)
            atomic_write_text(target, item.content)
