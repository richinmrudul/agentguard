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
UPLOAD_ARTIFACT_VERSION_COMMENT = "# v6.0.0"
DOWNLOAD_ARTIFACT = (
    "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131"
)
UPLOAD_SARIF = (
    "github/codeql-action/upload-sarif@"
    "6f5948dfacef28e207b48d0905cf90c03365536d"
)
HIDDEN_AGENTGUARD_UPLOAD_PATHS = {
    "agentguard-ci.yml": {
        ".agentguard/ci/*/report.json",
        ".agentguard/ci/*/report.md",
        ".agentguard/ci/*/pr-report.json",
        ".agentguard/ci/*/command_log.json",
        ".agentguard/ci/*/manifest.json",
    },
    "agentguard-gate.yml": {
        ".agentguard/suites/*/suite.json",
        ".agentguard/suites/*/suite.md",
        ".agentguard/suites/*/manifest.json",
    },
    "agentguard-pr-summary.yml": {
        ".agentguard/ci/*/report.json",
        ".agentguard/ci/*/report.md",
        ".agentguard/ci/*/command_log.json",
        ".agentguard/ci/*/manifest.json",
        ".agentguard/pr-report.json",
    },
    "agentguard-showcase.yml": {
        ".agentguard/showcase/showcase-summary.json",
        ".agentguard/showcase/showcase-summary.md",
        ".agentguard/showcase/showcase-overhead.json",
        ".agentguard/showcase/showcase-overhead.md",
        ".agentguard/showcase/suites/*/suite.json",
        ".agentguard/showcase/suites/*/suite.md",
        ".agentguard/showcase/suites/*/manifest.json",
    },
}
REQUIRED_HIDDEN_AGENTGUARD_EVIDENCE = {
    "agentguard-ci.yml": {
        ".agentguard/ci/*/report.json",
        ".agentguard/ci/*/report.md",
        ".agentguard/ci/*/command_log.json",
        ".agentguard/ci/*/pr-report.json",
    },
    "agentguard-gate.yml": {
        ".agentguard/suites/*/suite.json",
        ".agentguard/suites/*/suite.md",
        ".agentguard/suites/*/manifest.json",
    },
    "agentguard-pr-summary.yml": {
        ".agentguard/ci/*/report.json",
        ".agentguard/ci/*/report.md",
        ".agentguard/ci/*/command_log.json",
        ".agentguard/pr-report.json",
    },
    "agentguard-showcase.yml": {
        ".agentguard/showcase/showcase-summary.json",
        ".agentguard/showcase/showcase-summary.md",
        ".agentguard/showcase/showcase-overhead.json",
        ".agentguard/showcase/showcase-overhead.md",
        ".agentguard/showcase/suites/*/suite.json",
        ".agentguard/showcase/suites/*/suite.md",
        ".agentguard/showcase/suites/*/manifest.json",
    },
}
KNOWN_AGENTGUARD_ARTIFACT_FILENAMES = {
    "command_log.json",
    "manifest.json",
    "pr-report.json",
    "report.json",
    "report.md",
    "showcase-overhead.json",
    "showcase-overhead.md",
    "showcase-summary.json",
    "showcase-summary.md",
    "suite.json",
    "suite.md",
}


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


def _job(workflow: dict[str, Any], name: str) -> dict[str, Any]:
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    job = jobs[name]
    assert isinstance(job, dict)
    return job


def _job_steps(workflow: dict[str, Any], name: str) -> list[dict[str, Any]]:
    steps = _job(workflow, name)["steps"]
    assert isinstance(steps, list)
    return [step for step in steps if isinstance(step, dict)]


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


def _artifact_paths(step: dict[str, Any]) -> list[str]:
    with_config = step.get("with")
    assert isinstance(with_config, dict)
    paths = with_config.get("path")
    assert isinstance(paths, str)
    return [line.strip() for line in paths.splitlines() if line.strip()]


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
        assert "security-events" not in permissions
        assert "id-token" not in permissions
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


def test_agentguard_hidden_artifact_uploads_are_explicit_and_narrow() -> None:
    for name, expected_paths in HIDDEN_AGENTGUARD_UPLOAD_PATHS.items():
        workflow = _workflow(name)
        matching_steps = [
            step
            for step in _artifact_steps(workflow)
            if any(path.startswith(".agentguard/") for path in _artifact_paths(step))
        ]
        assert len(matching_steps) == 1, f"{name} should have one hidden upload"
        step = matching_steps[0]
        with_config = step["with"]
        paths = set(_artifact_paths(step))
        hidden_paths = {path for path in paths if path.startswith(".agentguard/")}

        assert hidden_paths == expected_paths
        assert with_config["include-hidden-files"] is True
        assert with_config["if-no-files-found"] == "error"
        assert step["if"] == "always()"
        for path in hidden_paths:
            assert "**" not in path
            assert "*" not in Path(path).name
            assert Path(path).name in KNOWN_AGENTGUARD_ARTIFACT_FILENAMES


def test_agentguard_required_hidden_evidence_absence_fails_clearly() -> None:
    for name, required_paths in REQUIRED_HIDDEN_AGENTGUARD_EVIDENCE.items():
        workflow = _workflow(name)
        steps = _steps(workflow)
        hidden_upload_index = next(
            index
            for index, step in enumerate(steps)
            if step.get("uses") == UPLOAD_ARTIFACT
            and any(path.startswith(".agentguard/") for path in _artifact_paths(step))
        )
        validation_index = next(
            index
            for index, step in enumerate(steps)
            if "Missing required AgentGuard artifact" in str(step.get("run", ""))
        )
        validation = steps[validation_index]
        validation_script = validation["run"]

        assert hidden_upload_index < validation_index
        assert validation["if"] == "always()"
        assert "exit \"$missing\"" in validation_script
        assert (
            "Missing required AgentGuard artifact: ${label}" in validation_script
            or "Missing required AgentGuard artifact: ${path}" in validation_script
        )
        for path in required_paths:
            assert path in validation_script


def test_upload_artifact_v6_configuration_is_preserved_for_every_example() -> None:
    for name in WORKFLOW_PATHS:
        text = _text(name)
        workflow = _workflow(name)
        artifacts = _artifact_steps(workflow)

        assert artifacts, f"{name} should use upload-artifact"
        assert f"uses: {UPLOAD_ARTIFACT} {UPLOAD_ARTIFACT_VERSION_COMMENT}" in text
        for step in artifacts:
            paths = _artifact_paths(step)
            with_config = step["with"]
            assert with_config["if-no-files-found"] == "error"
            if any(path.startswith(".agentguard/") for path in paths):
                assert with_config["include-hidden-files"] is True
            else:
                assert with_config["include-hidden-files"] is False


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
    assert UPLOAD_SARIF in _uses(workflow)
    assert _artifact_steps(workflow)


def test_sarif_junit_example_isolates_code_scanning_permissions() -> None:
    workflow = _workflow("agentguard-sarif-junit.yml")
    evaluate = _job(workflow, "evaluate")
    upload = _job(workflow, "upload-sarif")

    assert evaluate["permissions"] == {"contents": "read"}
    assert upload["permissions"] == {"security-events": "write"}
    assert "contents" not in upload["permissions"]
    assert "id-token" not in upload["permissions"]
    assert "id-token" not in evaluate["permissions"]
    assert upload["needs"] == "evaluate"

    checkout = next(
        step
        for step in _job_steps(workflow, "evaluate")
        if step.get("uses") == CHECKOUT
    )
    assert checkout["with"]["persist-credentials"] is False
    assert checkout["with"]["fetch-depth"] == 0
    assert CHECKOUT not in [
        step.get("uses") for step in _job_steps(workflow, "upload-sarif")
    ]


def test_sarif_junit_privileged_job_only_downloads_and_uploads_sarif() -> None:
    workflow = _workflow("agentguard-sarif-junit.yml")
    upload_steps = _job_steps(workflow, "upload-sarif")

    assert not any("run" in step for step in upload_steps)
    assert [step.get("uses") for step in upload_steps] == [
        DOWNLOAD_ARTIFACT,
        UPLOAD_SARIF,
    ]
    serialized = yaml.safe_dump(upload_steps)
    forbidden = [
        "actions/checkout",
        "pip install",
        "python -m pip",
        "pipx",
        "npm ",
        "pnpm ",
        "yarn ",
        "agentguard ci",
        "agentguard reports",
        "scripts/",
        "-e .",
    ]
    assert not any(term in serialized for term in forbidden)


def test_sarif_junit_artifact_handoff_and_conditions_are_explicit() -> None:
    workflow = _workflow("agentguard-sarif-junit.yml")
    evaluate_steps = _job_steps(workflow, "evaluate")
    upload_steps = _job_steps(workflow, "upload-sarif")

    upload_artifacts = [
        step for step in evaluate_steps if step.get("uses") == UPLOAD_ARTIFACT
    ]
    sarif_artifact = next(
        step for step in upload_artifacts if step["with"]["path"] == "agentguard.sarif"
    )
    junit_artifact = next(
        step
        for step in upload_artifacts
        if step["with"]["path"] == "agentguard-junit.xml"
    )
    download_artifact = next(
        step for step in upload_steps if step.get("uses") == DOWNLOAD_ARTIFACT
    )
    assert sarif_artifact["with"]["name"] == download_artifact["with"]["name"]
    assert sarif_artifact["with"]["name"].startswith("agentguard-sarif-")
    assert junit_artifact["with"]["name"].startswith("agentguard-junit-")
    assert sarif_artifact["with"]["name"] != junit_artifact["with"]["name"]
    for artifact in (sarif_artifact, junit_artifact):
        assert artifact["with"]["if-no-files-found"] == "error"
        assert artifact["with"]["retention-days"] == 7
        assert artifact["with"]["include-hidden-files"] is False

    condition = _job(workflow, "upload-sarif")["if"]
    assert "github.event_name == 'push'" in condition
    assert "github.event_name == 'pull_request'" in condition
    assert "github.event.pull_request.head.repo.full_name == github.repository" in condition
    assert "pull_request_target" not in yaml.safe_dump(workflow)


def test_sarif_junit_docs_describe_failure_and_trust_boundary() -> None:
    docs = Path("docs/ci-exports.md").read_text(encoding="utf-8")

    assert "two-job boundary" in docs
    assert "does not check out the repository" in docs
    assert "does not make SARIF parsing itself risk-free" in docs
    assert "no Code Scanning upload occurred" in docs
    assert "fork pull requests" in docs
    assert "security-events: write" in docs


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
