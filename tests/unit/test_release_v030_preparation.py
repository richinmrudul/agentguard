import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from agentguard import __version__
from agentguard.cli.main import app
from agentguard.config.json_schema import load_config_json_schema
from agentguard.project_init import _workflow_content


ROOT = Path(__file__).resolve().parents[2]


def _project() -> dict:
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]


def test_v030_source_distribution_import_and_cli_identity() -> None:
    project = _project()
    result = CliRunner().invoke(app, ["--version"])

    assert project["name"] == "agentguard-evals"
    assert project["version"] == "0.3.0"
    assert __version__ == "0.3.0"
    assert project["scripts"] == {"agentguard": "agentguard.cli.main:app"}
    assert result.exit_code == 0
    assert result.output.strip() == "0.3.0"


def test_v030_publish_workflow_retains_exact_release_boundary() -> None:
    source = (ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")
    workflow = yaml.safe_load(source)
    triggers = workflow.get("on", workflow.get(True))

    assert triggers == {"release": {"types": ["published"]}}
    assert workflow["permissions"] == {"contents": "read"}
    assert source.count("github.event.release.tag_name == 'v0.3.0'") == 2
    assert source.count('EXPECTED_VERSION: "0.3.0"') == 2
    assert "workflow_dispatch" not in triggers
    assert "pull_request" not in triggers
    assert "push" not in triggers
    assert workflow["jobs"]["build"]["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["publish"]["permissions"] == {
        "contents": "read",
        "id-token": "write",
    }
    assert workflow["jobs"]["publish"]["environment"]["name"] == "pypi"


def test_v030_changelog_and_candidate_record_are_truthful() -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    candidate = (
        ROOT / "docs/results/release-candidate-v0.3.0.md"
    ).read_text(encoding="utf-8")
    historical = (ROOT / "docs/results/release-v0.2.2.md").read_text(
        encoding="utf-8"
    )

    assert "## Unreleased\n\n## v0.3.0 - 2026-08-10" in changelog
    for feature in (
        "project initialization",
        "CI policy",
        "JSON Schema",
        "baseline-aware",
        "Node.js",
        "Go",
    ):
        assert feature in changelog
    assert "Status: **source candidate; not published**" in candidate
    assert "Production PyPI continues to serve v0.2.2" in candidate
    assert "has not been verified from public PyPI" in candidate
    assert "Deferred contained execution" not in candidate
    assert "Enforced contained execution remains deferred" in candidate
    assert "Released: 2026-07-28" in historical
    assert "agentguard-evals==0.3.0" not in historical


def test_v030_generated_workflows_and_schema_are_consistent() -> None:
    for project_type in ("Python", "Node.js", "Go"):
        source = _workflow_content(project_type)
        workflow = yaml.safe_load(source)
        assert "agentguard-evals==0.3.0" in source
        assert "pull_request_target" not in source
        assert workflow["permissions"] == {"contents": "read"}
        assert "secrets" not in source.lower()

    schema = load_config_json_schema()
    packaged = ROOT / "agentguard/schemas/agentguard-config-v1.schema.json"
    assert schema == json.loads(packaged.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"].endswith("/agentguard-config-v1.schema.json")


def test_current_version_surfaces_have_no_stale_v022_identity() -> None:
    current_sources = (
        ROOT / "pyproject.toml",
        ROOT / "agentguard/__init__.py",
        ROOT / "agentguard/project_init.py",
        ROOT / ".github/workflows/publish.yml",
        ROOT / "docs/results/adversarial-metrics.json",
        ROOT / "docs/results/showcase-metrics.json",
    )
    for path in current_sources:
        assert "0.2.2" not in path.read_text(encoding="utf-8"), path
