from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from io import BytesIO
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from agentguard import __version__
from agentguard.cli.main import app
from scripts.release_readiness import (
    build_readiness_summary,
    build_release_candidate_summary,
)
from scripts.validate_release_artifacts import (
    validate_artifacts,
    validate_ordinary_package_context,
    validate_strict_release_context,
    validate_strict_release_tag,
)


ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"
BUILD_SCRIPT = ROOT / "scripts/build_release.sh"
VALIDATION_SCRIPT = ROOT / "scripts/validate_release_artifacts.py"
READINESS_SCRIPT = ROOT / "scripts/release_readiness.py"
CI_WORKFLOW = ROOT / ".github/workflows/ci.yml"
LICENSE = ROOT / "LICENSE"
CHANGELOG = ROOT / "CHANGELOG.md"
README = ROOT / "README.md"
SHOWCASE_DOC = ROOT / "docs/showcase.md"
RELEASE_DOC = ROOT / "docs/release.md"
RELEASE_CHECKLIST = ROOT / "docs/release-checklist.md"
PORTFOLIO = ROOT / "docs/portfolio.md"
RELEASE_EVIDENCE = ROOT / "docs/results/release-v0.2.2.md"
RELEASE_EVIDENCE_V030 = ROOT / "docs/results/release-v0.3.0.md"
EVALUATION_DOC = ROOT / "docs/evaluation.md"
READINESS_JSON = ROOT / "docs/results/release-readiness-v0.2.json"
READINESS_MD = ROOT / "docs/results/release-readiness-v0.2.md"
RELEASE_CANDIDATE_JSON = ROOT / "docs/results/release-candidate-v0.2.0.json"
RELEASE_CANDIDATE_MD = ROOT / "docs/results/release-candidate-v0.2.0.md"
SUPPORTED_PYTHON = ["3.9", "3.10", "3.11", "3.12"]


def _load_pyproject() -> dict:
    if sys.version_info >= (3, 11):
        import tomllib

        return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))

    import tomli

    return tomli.loads(PYPROJECT.read_text(encoding="utf-8"))


def _metadata(description: str, version: str = "0.3.0") -> str:
    return (
        "Metadata-Version: 2.4\n"
        "Name: agentguard-evals\n"
        f"Version: {version}\n"
        "Requires-Python: >=3.9\n"
        "License-File: LICENSE\n"
        "\n"
        f"{description}\n"
    )


def _add_tar_text(archive: tarfile.TarFile, name: str, text: str) -> None:
    data = text.encode("utf-8")
    info = tarfile.TarInfo(name)
    info.size = len(data)
    archive.addfile(info, BytesIO(data))


def _write_release_artifacts(
    tmp_path: Path,
    wheel_description: str,
    sdist_description: str | None = None,
) -> tuple[Path, Path]:
    if sdist_description is None:
        sdist_description = wheel_description
    wheel = tmp_path / "agentguard_evals-0.3.0-py3-none-any.whl"
    sdist = tmp_path / "agentguard_evals-0.3.0.tar.gz"
    required_package_files = (
        "agentguard/__init__.py",
        "agentguard/cli/main.py",
        "agentguard/benchmarks/registry.py",
        "agentguard/core/orchestrator.py",
    )

    with zipfile.ZipFile(wheel, "w") as archive:
        for member in required_package_files:
            archive.writestr(member, "")
        archive.writestr(
            "agentguard_evals-0.3.0.dist-info/METADATA",
            _metadata(wheel_description),
        )
        archive.writestr(
            "agentguard_evals-0.3.0.dist-info/licenses/LICENSE",
            "MIT License\n",
        )

    with tarfile.open(sdist, "w:gz") as archive:
        for member in required_package_files:
            _add_tar_text(archive, f"agentguard_evals-0.3.0/{member}", "")
        _add_tar_text(
            archive,
            "agentguard_evals-0.3.0/PKG-INFO",
            _metadata(sdist_description),
        )
        _add_tar_text(archive, "agentguard_evals-0.3.0/LICENSE", "MIT License\n")

    return wheel, sdist


def _valid_long_description() -> str:
    return """# AgentGuard

Current release: v0.3.0, available from production PyPI.

## Current Proof

See docs/results/release-v0.3.0.md for current validation evidence.

## Historical Notes

v0.2.2 was an earlier production release.
The v0.2 readiness and release-candidate artifacts remain historical evidence:
docs/results/release-candidate-v0.2.0.md.
"""


@pytest.fixture(scope="module")
def release_artifacts(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    output_dir = tmp_path_factory.mktemp("release-artifacts")
    subprocess.run(
        ["bash", str(BUILD_SCRIPT), str(output_dir)],
        cwd=ROOT,
        check=True,
    )
    wheel = next(output_dir.glob("agentguard_evals-*.whl"))
    sdist = next(output_dir.glob("agentguard_evals-*.tar.gz"))
    return wheel, sdist


def test_project_metadata_declares_tested_python_range() -> None:
    pyproject = _load_pyproject()
    project = pyproject["project"]

    assert project["requires-python"] == ">=3.9"
    assert project["description"] == (
        "Local-first safety and reliability evaluation framework "
        "for AI coding agents."
    )
    assert project["dependencies"] == ["PyYAML>=6.0.0", "typer>=0.12.0"]
    assert project["license"] == "MIT"
    assert project["license-files"] == ["LICENSE"]
    classifiers = set(project["classifiers"])
    assert "License :: OSI Approved :: MIT License" not in classifiers
    for version in SUPPORTED_PYTHON:
        assert f"Programming Language :: Python :: {version}" in classifiers
    assert "Programming Language :: Python :: 3.13" not in classifiers
    assert project["scripts"]["agentguard"] == "agentguard.cli.main:app"
    assert pyproject["build-system"] == {
        "requires": ["setuptools>=77"],
        "build-backend": "setuptools.build_meta",
    }
    assert project["optional-dependencies"]["dev"].count("ruff==0.15.14") == 1


def test_package_version_sources_agree() -> None:
    project = _load_pyproject()["project"]
    project_version = project["version"]
    result = CliRunner().invoke(app, ["--version"])

    assert project["name"] == "agentguard-evals"
    assert project_version == __version__
    assert project_version == "0.3.0"
    assert project["scripts"] == {"agentguard": "agentguard.cli.main:app"}
    assert result.exit_code == 0
    assert result.output.strip() == project_version


def test_current_version_metadata_release_state_is_accepted(tmp_path: Path) -> None:
    wheel, sdist = _write_release_artifacts(tmp_path, _valid_long_description())

    validate_artifacts(wheel, sdist)


def test_packaged_metadata_rejects_older_version_as_current(
    tmp_path: Path,
) -> None:
    wheel, sdist = _write_release_artifacts(
        tmp_path,
        "# AgentGuard\n\nCurrent release: v0.2.2, available from production PyPI.\n",
    )

    with pytest.raises(AssertionError, match="older release 0.2.2 current"):
        validate_artifacts(wheel, sdist)


def test_packaged_metadata_rejects_current_version_as_unpublished(
    tmp_path: Path,
) -> None:
    wheel, sdist = _write_release_artifacts(
        tmp_path,
        "# AgentGuard\n\nAgentGuard v0.3.0 has not been published to PyPI.\n",
    )

    with pytest.raises(AssertionError, match="0.3.0 unpublished"):
        validate_artifacts(wheel, sdist)


def test_packaged_metadata_rejects_shipped_feature_as_release_candidate(
    tmp_path: Path,
) -> None:
    wheel, sdist = _write_release_artifacts(
        tmp_path,
        "# AgentGuard\n\nProject initialization remains a release candidate.\n",
    )

    with pytest.raises(AssertionError, match="shipped feature"):
        validate_artifacts(wheel, sdist)


def test_packaged_metadata_rejects_stale_current_release_evidence(
    tmp_path: Path,
) -> None:
    wheel, sdist = _write_release_artifacts(
        tmp_path,
        """# AgentGuard

Current release: v0.3.0.

## Current Proof

See docs/results/release-candidate-v0.2.0.md for current release evidence.
""",
    )

    with pytest.raises(AssertionError, match="stale version 0.2.0"):
        validate_artifacts(wheel, sdist)


def test_packaged_metadata_checks_wheel_and_sdist_descriptions(
    tmp_path: Path,
) -> None:
    wheel, sdist = _write_release_artifacts(
        tmp_path,
        _valid_long_description(),
        "# AgentGuard\n\nAgentGuard v0.3.0 is a source candidate.\n",
    )

    with pytest.raises(AssertionError, match="sdist long description"):
        validate_artifacts(wheel, sdist)


def test_packaged_metadata_ignores_changelog_history_and_historical_sections(
    tmp_path: Path,
) -> None:
    wheel, sdist = _write_release_artifacts(
        tmp_path,
        """# AgentGuard

Current release: v0.3.0.

## Changelog

### v0.2.0

Status: release candidate.
Production PyPI continues to serve v0.2.2.

## Historical Release Evidence

docs/results/release-candidate-v0.2.0.md remains useful historical evidence.
""",
    )

    validate_artifacts(wheel, sdist)


def test_ordinary_development_documentation_remains_usable() -> None:
    validate_ordinary_package_context(ROOT)


def _init_release_repository(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "agentguard@example.invalid"],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "AgentGuard Test"],
        cwd=tmp_path,
        check=True,
    )
    (tmp_path / "agentguard").mkdir()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "agentguard-evals"\n'
        'version = "0.3.0"\n'
        '[project.scripts]\n'
        'agentguard = "agentguard.cli.main:app"\n',
        encoding="utf-8",
    )
    (tmp_path / "agentguard/__init__.py").write_text(
        '__version__ = "0.3.0"\n',
        encoding="utf-8",
    )
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("tagged\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "tagged"], cwd=tmp_path, check=True)
    return tracked


def test_ordinary_validation_allows_post_release_commits(tmp_path: Path) -> None:
    tracked = _init_release_repository(tmp_path)
    subprocess.run(
        ["git", "tag", "-a", "v0.3.0", "-m", "AgentGuard v0.3.0"],
        cwd=tmp_path,
        check=True,
    )
    tracked.write_text("post-release documentation\n", encoding="utf-8")
    subprocess.run(
        ["git", "commit", "-qam", "post-release documentation"],
        cwd=tmp_path,
        check=True,
    )

    validate_ordinary_package_context(tmp_path)


def test_ordinary_validation_allows_simulated_merge_commit(tmp_path: Path) -> None:
    tracked = _init_release_repository(tmp_path)
    subprocess.run(
        ["git", "tag", "-a", "v0.3.0", "-m", "AgentGuard v0.3.0"],
        cwd=tmp_path,
        check=True,
    )
    tracked.write_text("merged documentation\n", encoding="utf-8")
    subprocess.run(
        ["git", "commit", "-qam", "Merge pull request"],
        cwd=tmp_path,
        check=True,
    )

    validate_ordinary_package_context(tmp_path)


def test_ordinary_validation_rejects_package_version_mismatch(tmp_path: Path) -> None:
    _init_release_repository(tmp_path)
    (tmp_path / "agentguard/__init__.py").write_text(
        '__version__ = "0.2.1"\n',
        encoding="utf-8",
    )

    with pytest.raises(AssertionError, match="Package version mismatch"):
        validate_ordinary_package_context(tmp_path)


def test_ordinary_validation_rejects_distribution_name_mismatch(
    tmp_path: Path,
) -> None:
    _init_release_repository(tmp_path)
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8").replace(
            'name = "agentguard-evals"',
            'name = "agentguard"',
        ),
        encoding="utf-8",
    )

    with pytest.raises(AssertionError, match="distribution"):
        validate_ordinary_package_context(tmp_path)


def test_strict_release_tag_must_be_annotated_and_point_to_head(
    tmp_path: Path,
) -> None:
    tracked = _init_release_repository(tmp_path)
    subprocess.run(
        ["git", "tag", "-a", "v0.3.0", "-m", "AgentGuard v0.3.0"],
        cwd=tmp_path,
        check=True,
    )

    validate_strict_release_tag(tmp_path, "0.3.0")

    tracked.write_text("new head\n", encoding="utf-8")
    subprocess.run(["git", "commit", "-qam", "new head"], cwd=tmp_path, check=True)

    with pytest.raises(AssertionError, match="current HEAD"):
        validate_strict_release_tag(tmp_path, "0.3.0")


def test_strict_release_tag_rejects_missing_or_mismatched_tag(
    tmp_path: Path,
) -> None:
    _init_release_repository(tmp_path)

    with pytest.raises(AssertionError, match="does not exist"):
        validate_strict_release_tag(tmp_path, "0.3.0")
    with pytest.raises(AssertionError, match="v0.3.1 does not exist"):
        validate_strict_release_tag(tmp_path, "0.3.1")


def test_strict_release_tag_rejects_lightweight_tag(tmp_path: Path) -> None:
    _init_release_repository(tmp_path)
    subprocess.run(["git", "tag", "v0.3.0"], cwd=tmp_path, check=True)

    with pytest.raises(AssertionError, match="must be annotated"):
        validate_strict_release_tag(tmp_path, "0.3.0")


def test_strict_release_context_rejects_distribution_mismatch(
    tmp_path: Path,
) -> None:
    _init_release_repository(tmp_path)
    subprocess.run(
        ["git", "tag", "-a", "v0.3.0", "-m", "AgentGuard v0.3.0"],
        cwd=tmp_path,
        check=True,
    )
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8").replace(
            'name = "agentguard-evals"',
            'name = "agentguard"',
        ),
        encoding="utf-8",
    )

    with pytest.raises(AssertionError, match="distribution"):
        validate_strict_release_context(tmp_path)


def test_release_readiness_documents_and_license_agree() -> None:
    license_text = LICENSE.read_text(encoding="utf-8")
    changelog = CHANGELOG.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    release_doc = RELEASE_DOC.read_text(encoding="utf-8")
    release_checklist = RELEASE_CHECKLIST.read_text(encoding="utf-8")
    portfolio = PORTFOLIO.read_text(encoding="utf-8")
    evaluation_doc = EVALUATION_DOC.read_text(encoding="utf-8")

    assert license_text.startswith("MIT License\n")
    assert "Copyright (c) 2026 Richin Mrudul" in license_text
    assert "## Unreleased" in changelog
    assert "## v0.2.2 - 2026-07-28" in changelog
    assert "## v0.2.1 - 2026-07-27" in changelog
    assert "## v0.2.0 - 2026-07-17" in changelog
    assert "## v0.1.0 - Released" in changelog
    for heading in (
        "### Added",
        "### Changed",
        "### Fixed",
        "### Security/Safety",
        "### Known Limitations",
    ):
        assert heading in changelog
    for target in ("LICENSE", "CHANGELOG.md", "docs/release.md"):
        assert f"]({target})" in readme
    for target in (
        "docs/results/release-readiness-v0.2.md",
        "docs/results/release-candidate-v0.2.0.md",
        "examples/github-actions/",
        "docs/showcase.md",
        "docs/static-site.md",
    ):
        assert target in readme
    assert "no external-agent benchmark results are" in evaluation_doc
    assert "published with v0.1.0" in evaluation_doc
    forbidden_publish_commands = (
        "twine upload",
        "uv publish",
        "hatch publish",
        "flit publish",
        "poetry publish",
    )
    assert not any(command in release_doc for command in forbidden_publish_commands)
    for document in (readme, release_doc):
        assert "v0.2.0" in document
    for document in (readme, release_doc, portfolio):
        assert "v0.3.0" in document
    for document in (readme, portfolio):
        assert "published" in document
    for stale_instruction in (
        'git tag -a v0.2.0 -m "AgentGuard v0.2.0"',
        "git push origin v0.2.0",
        "gh release create v0.2.0",
        "v0.2.0 has not been tagged",
        "no v0.2.0 GitHub release",
    ):
        assert stale_instruction not in "\n".join(
            (readme, release_doc, release_checklist, portfolio)
        )
    assert 'git tag -a "v${VERSION}"' in release_doc
    assert 'gh release create "v${VERSION}"' in release_doc
    assert ".github/workflows/publish.yml" in release_doc
    assert "production PyPI Trusted Publishing" in release_doc
    assert "`agentguard-evals`" in release_doc
    assert "v0.2.1 is a valid published GitHub release" in release_doc
    assert RELEASE_EVIDENCE.exists()
    assert RELEASE_EVIDENCE_V030.exists()


def test_v0_2_2_public_release_documentation_is_consistent() -> None:
    readme = README.read_text(encoding="utf-8")
    changelog = CHANGELOG.read_text(encoding="utf-8")
    release_doc = RELEASE_DOC.read_text(encoding="utf-8")
    release_checklist = RELEASE_CHECKLIST.read_text(encoding="utf-8")
    portfolio = PORTFOLIO.read_text(encoding="utf-8")
    evidence = RELEASE_EVIDENCE.read_text(encoding="utf-8")
    current_docs = "\n".join(
        (readme, changelog, release_doc, release_checklist, portfolio, evidence)
    )

    assert "agentguard-evals==0.2.2" in current_docs
    assert "import agentguard" in current_docs
    assert "`agentguard`" in current_docs
    assert "1,157" in evidence
    assert "15" in evidence
    assert "OIDC Trusted Publishing" in evidence
    assert "byte-identical" in evidence
    assert "v0.2.1 remains a valid GitHub-only release" in evidence
    assert (
        "https://github.com/richinmrudul/agentguard/releases/tag/v0.2.2"
        in current_docs
    )
    assert "https://pypi.org/project/agentguard-evals/0.2.2/" in current_docs
    assert "PyPI publication remains deferred" not in current_docs


def test_v0_3_0_public_release_documentation_is_consistent() -> None:
    readme = README.read_text(encoding="utf-8")
    showcase = SHOWCASE_DOC.read_text(encoding="utf-8")
    release_doc = RELEASE_DOC.read_text(encoding="utf-8")
    portfolio = PORTFOLIO.read_text(encoding="utf-8")
    evidence = RELEASE_EVIDENCE_V030.read_text(encoding="utf-8")
    current_docs = "\n".join((readme, showcase, release_doc, portfolio, evidence))

    assert "agentguard-evals==0.3.0" in current_docs
    assert "import agentguard" in current_docs
    assert "Install the current released v0.3.0 command" in showcase
    assert "results/release-v0.3.0.md" in showcase
    assert "Install the released v0.2.2 command" not in showcase
    assert "1,401" in evidence
    assert "15" in evidence
    assert "89.03%" in evidence
    assert "OIDC Trusted Publishing" in evidence
    assert "byte-identical" in evidence
    assert "release-candidate-v0.3.0.md" in evidence
    assert (
        "https://github.com/richinmrudul/agentguard/releases/tag/v0.3.0"
        in current_docs
    )
    assert "https://pypi.org/project/agentguard-evals/0.3.0/" in current_docs
    assert "Published PyPI metadata is immutable" in readme
    assert "Published PyPI metadata is immutable" in release_doc
    assert (
        "446ba25ef9f3eebb2d056606e6493b45ab8d0f4a6431e4d3ecabbfff859e8e26"
        in evidence
    )
    assert (
        "2c156ff2817b38158dd7fbbf04122ade551b8bda9d4f1cc4a4d59a6ea6182fdf"
        in evidence
    )


def test_release_readiness_script_and_artifacts_are_valid() -> None:
    assert READINESS_SCRIPT.exists()
    artifact = json_load(READINESS_JSON)
    markdown = READINESS_MD.read_text(encoding="utf-8")
    generated = build_readiness_summary()

    assert artifact == generated
    assert artifact["schema"] == "agentguard.release-readiness"
    assert artifact["schema_version"] == 1
    assert artifact["release"] == "v0.2.0"
    assert artifact["recommendation"] == "released"
    assert artifact["package_metadata"]["version"] == "0.2.0"
    assert artifact["package_metadata"]["current_version"] == __version__
    assert artifact["package_metadata"]["console_script"] == (
        "agentguard.cli.main:app"
    )
    assert artifact["package_metadata"]["supported_python"] == SUPPORTED_PYTHON
    assert artifact["showcase_metrics"]["unsafe_scenarios_detected"] == 5
    assert artifact["showcase_metrics"]["safe_scenarios_allowed"] == 1
    assert artifact["showcase_metrics"]["false_positive_count"] == 0
    assert artifact["showcase_metrics"]["false_negative_count"] == 0
    assert artifact["adversarial_metrics"]["total_scenarios"] == 10
    assert set(artifact["adversarial_metrics"]["builtin_detector_coverage"]) == {
        "github-token-shape",
        "npm-token-shape",
        "private-key-header",
    }
    assert artifact["watcher_coverage"]["modes"] == ["auto", "polling", "disabled"]
    assert "filesystem watcher foundation" in artifact["post_v0_1_feature_summary"]
    assert all(item["exists"] for item in artifact["required_docs"])
    assert all(item["exists"] for item in artifact["required_examples"])
    assert all(item["exists"] for item in artifact["required_scripts"])
    assert all(
        item.get("help_rendered") or item.get("version_matches_package")
        for item in artifact["cli_smoke"]
    )
    assert "Status: **released**" in markdown
    assert "published as a GitHub release" in markdown
    assert "PyPI publishing" in markdown


def test_release_candidate_artifacts_are_valid() -> None:
    artifact = json_load(RELEASE_CANDIDATE_JSON)
    markdown = RELEASE_CANDIDATE_MD.read_text(encoding="utf-8")
    generated = build_release_candidate_summary()

    assert artifact == generated
    assert artifact["schema"] == "agentguard.release-candidate"
    assert artifact["schema_version"] == 1
    assert artifact["release"] == "v0.2.0"
    assert artifact["status"] == "released"
    assert artifact["recommendation"] == "GitHub release published; PyPI deferred"
    assert artifact["package_metadata"]["version"] == "0.2.0"
    assert artifact["package_metadata"]["current_version"] == __version__
    assert artifact["package_metadata"]["console_script"] == (
        "agentguard.cli.main:app"
    )
    assert artifact["package_build_validation"]["published"] is False
    assert artifact["package_smoke"]["command"] == "bash scripts/package_smoke.sh"
    assert artifact["showcase_metrics"]["unsafe_scenarios_detected"] == 5
    assert artifact["showcase_metrics"]["safe_scenarios_allowed"] == 1
    assert "No syscall-level interception is included." in artifact[
        "known_limitations"
    ]
    assert artifact["not_performed_by_this_pr"] == ["PyPI publication"]
    assert "post_merge_release_commands" not in artifact
    assert artifact["adversarial_metrics"]["total_scenarios"] == 10
    assert "published as a GitHub release" in markdown
    assert "gh release create v0.2.0" not in markdown
    assert "PyPI publication" in markdown


def test_release_readiness_artifacts_are_sanitized() -> None:
    combined = (
        READINESS_JSON.read_text(encoding="utf-8")
        + "\n"
        + READINESS_MD.read_text(encoding="utf-8")
        + "\n"
        + RELEASE_CANDIDATE_JSON.read_text(encoding="utf-8")
        + "\n"
        + RELEASE_CANDIDATE_MD.read_text(encoding="utf-8")
    )

    forbidden_patterns = [
        r"AGENTGUARD_SHOWCASE_SECRET",
        r"AGENTGUARD_SECRET",
        r"diff --git",
        r"/Users/",
        r"/private/",
        r"/tmp/",
        r"[A-Za-z]:\\\\",
        r"richinmrudul",
        r"\bHOME=",
        r"\bTMPDIR=",
        r"javascript:",
        r"file:",
    ]
    for pattern in forbidden_patterns:
        assert not re.search(pattern, combined)


def test_validate_release_artifacts_no_args_checks_v0_2_readiness() -> None:
    result = subprocess.run(
        [sys.executable, str(VALIDATION_SCRIPT)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "Release readiness artifacts validated." in result.stdout


def test_release_readiness_referenced_paths_exist() -> None:
    artifact = json_load(READINESS_JSON)

    for section in ("required_docs", "required_examples", "required_scripts"):
        for item in artifact[section]:
            path = ROOT / item["path"]
            assert path.exists(), item["path"]


def test_no_generated_release_outputs_are_tracked() -> None:
    tracked = subprocess.run(
        ["git", "ls-files"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    forbidden = (
        "dist/",
        "build/",
        ".agentguard/",
        ".venv/",
    )
    assert not any(path.startswith(forbidden) for path in tracked)
    assert not any(
        path.endswith((".egg-info/PKG-INFO", ".egg-info/SOURCES.txt"))
        for path in tracked
    )


def test_build_release_script_is_executable_and_never_publishes() -> None:
    assert BUILD_SCRIPT.exists()
    assert os.access(BUILD_SCRIPT, os.X_OK)
    assert VALIDATION_SCRIPT.exists()

    script = BUILD_SCRIPT.read_text(encoding="utf-8")
    assert "set -euo pipefail" in script
    assert 'ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)' in script
    assert "-m build" in script
    assert "--no-isolation" in script
    assert "--wheel" in script
    assert "--sdist" in script
    assert 'rm -rf "$ROOT_DIR/build"' in script
    assert "validate_release_artifacts.py" in script
    assert "--ordinary-ci" in script
    assert "--strict-release-tag" in script
    assert "--check-version-tag" not in script
    assert "nothing was published" in script
    assert "twine upload" not in script
    assert "gh release" not in script


def test_ci_workflow_separates_compatibility_docker_and_package_jobs() -> None:
    workflow = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]

    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"]["cancel-in-progress"] is True
    assert jobs["compatibility"]["strategy"]["fail-fast"] is False
    assert jobs["compatibility"]["strategy"]["matrix"]["python-version"] == (
        SUPPORTED_PYTHON
    )
    assert 'python -m pytest -m "not docker and not package"' in str(
        jobs["compatibility"]
    )
    assert "python -m pytest" in str(jobs["integration"])
    assert (
        "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f"
        in str(jobs["package"])
    )
    assert "scripts/build_release.sh --ordinary-ci" in str(jobs["package"])
    assert "--strict-release-tag" not in str(jobs["package"])
    package_checkout = jobs["package"]["steps"][0]
    assert package_checkout["with"]["fetch-depth"] == 0
    assert "publish" not in jobs


@pytest.mark.package
def test_wheel_and_sdist_contents(release_artifacts: tuple[Path, Path]) -> None:
    wheel, sdist = release_artifacts

    subprocess.run(
        [sys.executable, str(VALIDATION_SCRIPT), str(wheel), str(sdist)],
        cwd=ROOT,
        check=True,
    )

    with zipfile.ZipFile(wheel) as archive:
        wheel_members = archive.namelist()
    with tarfile.open(sdist, "r:gz") as archive:
        sdist_members = archive.getnames()

    assert any(name.endswith(".dist-info/entry_points.txt") for name in wheel_members)
    schema_member = "agentguard/schemas/agentguard-config-v1.schema.json"
    assert schema_member in wheel_members
    assert any(name.endswith(f"/{schema_member}") for name in sdist_members)
    assert not any("/examples/" in name for name in sdist_members)
    assert not any("/docs/" in name for name in sdist_members)
    assert not any("/tests/" in name for name in sdist_members)


@pytest.mark.package
def test_installed_wheel_runs_outside_repository(
    release_artifacts: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    wheel, _ = release_artifacts
    venv_dir = tmp_path / "wheel-venv"
    work_dir = tmp_path / "outside-repository"
    subprocess.run(
        [sys.executable, "-m", "venv", "--system-site-packages", str(venv_dir)],
        check=True,
    )
    work_dir.mkdir()

    python = venv_dir / "bin/python"
    console = venv_dir / "bin/agentguard"
    subprocess.run(
        [str(python), "-m", "pip", "install", "--no-deps", str(wheel)],
        check=True,
    )
    assert shutil.which("agentguard", path=str(venv_dir / "bin")) == str(console)

    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    version_result = subprocess.run(
        [str(console), "--version"],
        cwd=work_dir,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert version_result.stdout.strip() == __version__
    subprocess.run([str(console), "--help"], cwd=work_dir, env=env, check=True)

    import_result = subprocess.run(
        [
            str(python),
            "-c",
            (
                "import agentguard, pathlib, sys; "
                "path = pathlib.Path(agentguard.__file__).resolve(); "
                "print(path); "
                "assert pathlib.Path(sys.prefix).resolve() in path.parents"
            ),
        ],
        cwd=work_dir,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert str(venv_dir.resolve()) in import_result.stdout

    subprocess.run(
        [
            str(python),
            "-c",
            (
                "from agentguard.config.json_schema import "
                "load_config_json_schema; "
                "schema = load_config_json_schema(); "
                "assert schema['$schema'] == "
                "'https://json-schema.org/draft/2020-12/schema'"
            ),
        ],
        cwd=work_dir,
        env=env,
        check=True,
    )

    metadata_result = subprocess.run(
        [
            str(python),
            "-c",
            (
                "from importlib.metadata import PackageNotFoundError, "
                "distribution; "
                "d = distribution('agentguard-evals'); "
                "assert d.metadata['Name'] == 'agentguard-evals'; "
                "assert d.version == '0.3.0'; "
                "\ntry: distribution('agentguard')\n"
                "except PackageNotFoundError: pass\n"
                "else: raise AssertionError('legacy distribution is installed')"
            ),
        ],
        cwd=work_dir,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert metadata_result.returncode == 0

    registry_result = subprocess.run(
        [str(console), "benchmarks", "list"],
        cwd=work_dir,
        env=env,
        capture_output=True,
        text=True,
    )
    assert registry_result.returncode == 2
    assert "examples/benchmarks/registry.yaml" in registry_result.stderr


def json_load(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data
