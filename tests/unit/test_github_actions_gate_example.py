import re
import shlex
from pathlib import Path
from typing import Any

import yaml


WORKFLOW_DIR = Path("examples/github-actions")
WORKFLOW_PATHS = {
    "agentguard-ci.yml",
    "agentguard-gate.yml",
    "agentguard-pr-summary.yml",
    "agentguard-sarif-junit.yml",
    "agentguard-showcase.yml",
}
CORE_SUITE_PATH = Path("examples/suites/core.yaml")
CHECKOUT = "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd"
SETUP_PYTHON = (
    "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405"
)
UPLOAD_ARTIFACT = (
    "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f"
)


def _workflow_path(name: str) -> Path:
    return WORKFLOW_DIR / name


def _workflow(name: str) -> dict[str, Any]:
    path = _workflow_path(name)
    assert path.exists()
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _text(name: str) -> str:
    return _workflow_path(name).read_text(encoding="utf-8")


def _steps(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    steps: list[dict[str, Any]] = []
    for job in jobs.values():
        assert isinstance(job, dict)
        job_steps = job["steps"]
        assert isinstance(job_steps, list)
        steps.extend(step for step in job_steps if isinstance(step, dict))
    return steps


def _run_commands(workflow: dict[str, Any]) -> list[str]:
    commands: list[str] = []
    for step in _steps(workflow):
        command = step.get("run")
        if isinstance(command, str):
            commands.append(command)
    return commands


def _uses(workflow: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for step in _steps(workflow):
        action = step.get("uses")
        if isinstance(action, str):
            values.append(action)
    return values


def _artifact_steps(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        step
        for step in _steps(workflow)
        if step.get("uses") == UPLOAD_ARTIFACT
    ]


def test_github_actions_examples_parse_and_use_supported_actions() -> None:
    for name in WORKFLOW_PATHS:
        workflow = _workflow(name)
        assert "jobs" in workflow
        used_actions = set(_uses(workflow))
        assert CHECKOUT in used_actions
        assert SETUP_PYTHON in used_actions
        assert not any("@v1" in action or "@v2" in action for action in used_actions)


def test_github_actions_examples_have_minimal_permissions() -> None:
    for name in WORKFLOW_PATHS:
        workflow = _workflow(name)
        permissions = workflow.get("permissions")
        assert isinstance(permissions, dict), f"{name} should declare permissions"
        assert permissions["contents"] == "read"
        assert "pull-requests" not in permissions
        assert "checks" not in permissions
        if name == "agentguard-sarif-junit.yml":
            assert permissions["security-events"] == "write"
        else:
            assert set(permissions) == {"contents"}


def test_github_actions_examples_upload_expected_artifacts() -> None:
    for name in WORKFLOW_PATHS:
        workflow = _workflow(name)
        artifacts = _artifact_steps(workflow)
        assert artifacts, f"{name} should upload AgentGuard artifacts"
        serialized = yaml.safe_dump(artifacts)
        if name == "agentguard-sarif-junit.yml":
            assert "agentguard-junit.xml" in serialized
        elif name == "agentguard-showcase.yml":
            assert "docs/results/showcase-metrics.json" in serialized
            assert ".agentguard/showcase" in serialized
        elif name == "agentguard-gate.yml":
            assert ".agentguard/suites" in serialized
        else:
            assert ".agentguard/ci" in serialized


def test_basic_ci_gate_example_fails_pr_and_writes_summary() -> None:
    workflow = _workflow("agentguard-ci.yml")
    text = _text("agentguard-ci.yml")

    assert "pull_request:" in text
    assert 'python -m pip install -e ".[dev]"' in text
    assert "agentguard ci" in text
    assert "--config agentguard.yaml" in text
    assert 'AGENTGUARD_BASE_SHA: ${{ github.event.pull_request.base.sha }}' in text
    assert '--base "$AGENTGUARD_BASE_SHA"' in text
    assert "--head HEAD" in text
    assert "--github-summary" in text
    assert "--allow-fail-result" not in text
    assert _artifact_steps(workflow)


def test_pr_summary_workflow_uses_github_step_summary_safely() -> None:
    text = _text("agentguard-pr-summary.yml")

    assert "agentguard ci" in text
    assert "--github-summary" in text
    assert "GITHUB_STEP_SUMMARY" in text
    assert "agentguard-pr-summary" in text
    assert "--baseline-report" in text
    assert "--pr-report" in text
    assert "--github-annotations" in text
    assert "git show" in text
    assert "^[[0-9a-f]{40}$" not in text
    assert "^[0-9a-f]{40}$" in text
    assert '"${cmd[@]}"' in text
    assert "pull request checkout" in text
    assert "pull_request_target" not in text
    assert "raw diff" not in text.lower()
    assert "secret value" not in text.lower()


def test_showcase_workflow_runs_metrics_and_uploads_docs_results() -> None:
    text = _text("agentguard-showcase.yml")

    assert "python scripts/showcase_metrics.py" in text
    assert "docs/results/showcase-summary.json" in text
    assert "docs/results/showcase-metrics.json" in text
    assert ".agentguard/showcase" in text


def test_suite_gate_example_still_uses_core_suite_baseline() -> None:
    workflow = _workflow("agentguard-gate.yml")
    text = _text("agentguard-gate.yml")

    assert CORE_SUITE_PATH.exists()
    assert "agentguard gate suite" in text
    assert "--save-baseline /tmp/agentguard-core-baseline.json" in text
    assert "--baseline /tmp/agentguard-core-baseline.json" in text
    assert str(CORE_SUITE_PATH) in text
    assert _artifact_steps(workflow)


def test_sarif_junit_example_exports_existing_reports() -> None:
    workflow = _workflow("agentguard-sarif-junit.yml")
    text = _text("agentguard-sarif-junit.yml")

    assert "agentguard reports export-sarif .agentguard/ci" in text
    assert "agentguard reports export-junit .agentguard/ci" in text
    assert "github/codeql-action/upload-sarif@v3" in _uses(workflow)
    assert _artifact_steps(workflow)


def test_workflow_commands_reference_existing_local_assets_or_placeholders() -> None:
    placeholder_paths = {"agentguard.yaml"}
    for name in WORKFLOW_PATHS:
        for command in _run_commands(_workflow(name)):
            for line in command.splitlines():
                stripped = line.strip().rstrip("\\")
                if not stripped or stripped.startswith(("#", "echo", "{", "}")):
                    continue
                try:
                    tokens = shlex.split(stripped)
                except ValueError:
                    continue
                for token in tokens:
                    if token in placeholder_paths:
                        continue
                    if token.startswith(("examples/", "scripts/", "docs/")):
                        assert Path(token).exists(), (
                            f"{name} references missing path {token!r}"
                        )


def test_docs_reference_github_actions_examples() -> None:
    docs = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [
            Path("README.md"),
            Path("docs/github-actions.md"),
            Path("docs/ci-exports.md"),
            Path("docs/showcase.md"),
        ]
    )

    for name in WORKFLOW_PATHS:
        path = f"examples/github-actions/{name}"
        assert path in docs


def test_workflows_do_not_embed_local_paths_or_secret_like_values() -> None:
    combined = "\n".join(_text(name) for name in WORKFLOW_PATHS)

    assert not re.search(r"(/Users/|/private/|[A-Za-z]:\\\\)", combined)
    assert "AGENTGUARD_SHOWCASE_SECRET_EXAMPLE" not in combined
    assert "pull_request_target" not in combined
    assert "origin/${{ github.base_ref }}" not in combined
    assert not re.search(
        r"(ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})",
        combined,
    )


def test_workflow_run_bodies_never_interpolate_github_event_data() -> None:
    workflow_paths = [
        *sorted(Path(".github/workflows").glob("*.yml")),
        *sorted(WORKFLOW_DIR.glob("*.yml")),
    ]
    forbidden = re.compile(r"\$\{\{\s*github\.(?:event(?:\.|\s)|base_ref\b)")

    for path in workflow_paths:
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(workflow, dict)
        for command in _run_commands(workflow):
            assert forbidden.search(command) is None, (
                f"{path} interpolates GitHub event data into shell source"
            )
