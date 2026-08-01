import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml


ROOT = Path(__file__).resolve().parents[2]
MKDOCS = ROOT / "mkdocs.yml"
DOCS = ROOT / "docs"
HOMEPAGE = DOCS / "index.md"
README = ROOT / "README.md"
HOSTED_DOCS = DOCS / "hosted-documentation.md"
PAGES_EVIDENCE = DOCS / "results" / "github-pages-v0.2.2.md"
WORKFLOW_PATH = ROOT / ".github/workflows/docs.yml"
PYPROJECT = ROOT / "pyproject.toml"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


class _MkDocsLoader(yaml.SafeLoader):
    pass


_MkDocsLoader.add_multi_constructor(
    "tag:yaml.org,2002:python/name:",
    lambda _loader, suffix, _node: f"python/name:{suffix}",
)


def _mkdocs() -> dict[str, Any]:
    config = yaml.load(MKDOCS.read_text(encoding="utf-8"), Loader=_MkDocsLoader)
    assert isinstance(config, dict)
    return config


def _workflow() -> dict[str, Any]:
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    return workflow


def _triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    triggers = workflow.get("on", workflow.get(True))
    assert isinstance(triggers, dict)
    return triggers


def _local_nav_targets(value: Any) -> list[str]:
    if isinstance(value, str):
        return [] if urlsplit(value).scheme else [value]
    if isinstance(value, list):
        return [
            target
            for item in value
            for target in _local_nav_targets(item)
        ]
    if isinstance(value, dict):
        return [
            target
            for item in value.values()
            for target in _local_nav_targets(item)
        ]
    return []


def test_mkdocs_configuration_and_navigation_are_hostable() -> None:
    config = _mkdocs()

    assert config["site_name"] == "AgentGuard"
    assert config["site_url"] == "https://richinmrudul.github.io/agentguard/"
    assert config["repo_url"] == "https://github.com/richinmrudul/agentguard"
    assert config["edit_uri"] == "edit/main/docs/"
    assert config["theme"]["name"] == "material"
    assert config["plugins"] == ["search"]
    assert "content.code.copy" in config["theme"]["features"]
    assert len(config["theme"]["palette"]) == 2
    assert config["extra_css"] == ["stylesheets/extra.css"]
    assert config["extra_javascript"] == [
        "https://unpkg.com/mermaid@11.16.0/dist/mermaid.min.js"
    ]

    targets = _local_nav_targets(config["nav"])
    assert targets
    for target in targets:
        path_text = unquote(urlsplit(target).path)
        path = (DOCS / path_text).resolve()
        assert DOCS.resolve() in (path, *path.parents), target
        assert path.is_file(), target


def test_homepage_contains_current_identity_evidence_and_trust_boundary() -> None:
    homepage = HOMEPAGE.read_text(encoding="utf-8")

    for required in (
        "local-first",
        "observable evidence",
        "AgentGuard v0.2.2",
        "agentguard-evals",
        "python -m pip install agentguard-evals",
        "agentguard --version",
        "agentguard --help",
        "Python 3.9–3.12",
        "1,170",
        "15 documented",
        "5/5 unsafe",
        "1/1",
        "10 deterministic",
        "not inherently\n    sandboxed",
        "not a perfect\n    security boundary",
    ):
        assert required in homepage

    for target in (
        "quickstart.md",
        "architecture.md",
        "benchmarks.md",
        "evaluation.md",
        "online-guard.md",
        "ci-exports.md",
        "static-site.md",
        "traces.md",
        "replay.md",
        "release.md",
        "https://pypi.org/project/agentguard-evals/0.2.2/",
        "https://github.com/richinmrudul/agentguard",
    ):
        assert target in homepage


def test_live_pages_status_and_deployment_evidence_are_consistent() -> None:
    readme = README.read_text(encoding="utf-8")
    hosted_docs = HOSTED_DOCS.read_text(encoding="utf-8")
    evidence = PAGES_EVIDENCE.read_text(encoding="utf-8")
    site_url = "https://richinmrudul.github.io/agentguard/"
    workflow_url = (
        "https://github.com/richinmrudul/agentguard/actions/runs/30705834800"
    )

    assert "is live" in readme
    assert "on GitHub Pages" in readme
    assert "deployment evidence](docs/results/github-pages-v0.2.2.md)" in readme
    assert site_url in readme
    assert "GitHub Pages is enabled with **GitHub Actions**" in hosted_docs
    assert "results/github-pages-v0.2.2.md" in hosted_docs
    assert "build_type: workflow" in evidence
    assert workflow_url in evidence
    assert "Successful run attempt: 2" in evidence
    assert "41 URLs listed in the sitemap returned HTTP 200" in evidence
    assert "No custom domain" in evidence
    assert "after the repository's Pages workflow is enabled" not in readme


def test_hosted_markdown_links_resolve_without_escaping_docs() -> None:
    failures: list[str] = []
    for source in DOCS.rglob("*.md"):
        text = source.read_text(encoding="utf-8")
        for raw_target in MARKDOWN_LINK.findall(text):
            target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or target.startswith(("#", "mailto:")):
                continue
            path_text = unquote(parsed.path)
            if not path_text:
                continue
            resolved = (source.parent / path_text).resolve()
            if DOCS.resolve() not in (resolved, *resolved.parents):
                failures.append(f"{source.relative_to(ROOT)} escapes docs: {target}")
            elif not resolved.exists():
                failures.append(f"{source.relative_to(ROOT)} missing: {target}")

    assert failures == []


def test_docs_workflow_builds_prs_but_deploys_only_main() -> None:
    workflow = _workflow()
    triggers = _triggers(workflow)
    build = workflow["jobs"]["build"]
    deploy = workflow["jobs"]["deploy"]
    source = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert set(triggers) == {"pull_request", "push", "workflow_dispatch"}
    assert triggers["push"]["branches"] == ["main"]
    assert "pull_request" in build["if"]
    assert "refs/heads/main" in build["if"]
    assert deploy["needs"] == "build"
    assert "github.event_name != 'pull_request'" in deploy["if"]
    assert "github.ref == 'refs/heads/main'" in deploy["if"]
    assert deploy["environment"]["name"] == "github-pages"
    assert deploy["environment"]["url"] == (
        "${{ steps.deployment.outputs.page_url }}"
    )
    assert "python -m mkdocs build --strict" in source

    configure = next(
        step for step in build["steps"] if "configure-pages@" in step.get("uses", "")
    )
    upload = next(
        step
        for step in build["steps"]
        if "upload-pages-artifact@" in step.get("uses", "")
    )
    for step in (configure, upload):
        assert "github.event_name != 'pull_request'" in step["if"]
        assert "github.ref == 'refs/heads/main'" in step["if"]
    assert upload["with"]["path"] == "site/"


def test_docs_workflow_permissions_actions_and_credentials_are_safe() -> None:
    workflow = _workflow()
    build = workflow["jobs"]["build"]
    deploy = workflow["jobs"]["deploy"]
    source = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert workflow["permissions"] == {"contents": "read"}
    assert build["permissions"] == {"contents": "read"}
    assert deploy["permissions"] == {
        "contents": "read",
        "pages": "write",
        "id-token": "write",
    }
    assert "id-token" not in workflow["permissions"]
    assert "id-token" not in build["permissions"]

    actions = [
        step["uses"]
        for job in workflow["jobs"].values()
        for step in job["steps"]
        if "uses" in step
    ]
    for action in actions:
        repository, ref = action.rsplit("@", 1)
        assert repository.startswith("actions/")
        assert FULL_SHA.fullmatch(ref), action

    lowered = source.lower()
    assert "secrets." not in lowered
    assert "password" not in lowered
    assert "pypi" not in lowered
    assert "testpypi" not in lowered
    assert "publish.yml" not in lowered


def test_docs_tooling_is_optional_and_generated_site_is_ignored() -> None:
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        import tomli as tomllib

    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    runtime = project["dependencies"]
    docs = project["optional-dependencies"]["docs"]

    assert all("mkdocs" not in dependency.lower() for dependency in runtime)
    assert docs == [
        "mkdocs>=1.6.1,<2.0.0",
        "mkdocs-material>=9.7.7,<10.0.0",
    ]
    assert "site/" in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    tracked_site = subprocess.run(
        ["git", "ls-files", "site"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert tracked_site.stdout == ""


def test_hosted_content_has_no_private_paths_or_testpypi_install_source() -> None:
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            MKDOCS,
            HOMEPAGE,
            DOCS / "quickstart.md",
            DOCS / "hosted-documentation.md",
        )
    )

    assert not re.search(r"(/Users/|/private/var/|[A-Za-z]:\\\\)", combined)
    assert "--index-url https://test.pypi.org" not in combined.lower()
    assert "pip install agentguard-evals" in combined
    assert "import agentguard" in combined
    assert "agentguard --version" in combined
