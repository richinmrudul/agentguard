import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from importlib.metadata import version as installed_version
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


ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"
BUILD_SCRIPT = ROOT / "scripts/build_release.sh"
VALIDATION_SCRIPT = ROOT / "scripts/validate_release_artifacts.py"
READINESS_SCRIPT = ROOT / "scripts/release_readiness.py"
CI_WORKFLOW = ROOT / ".github/workflows/ci.yml"
LICENSE = ROOT / "LICENSE"
CHANGELOG = ROOT / "CHANGELOG.md"
README = ROOT / "README.md"
RELEASE_DOC = ROOT / "docs/release.md"
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


@pytest.fixture(scope="module")
def release_artifacts(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    output_dir = tmp_path_factory.mktemp("release-artifacts")
    subprocess.run(
        ["bash", str(BUILD_SCRIPT), str(output_dir)],
        cwd=ROOT,
        check=True,
    )
    wheel = next(output_dir.glob("agentguard-*.whl"))
    sdist = next(output_dir.glob("agentguard-*.tar.gz"))
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
    project_version = _load_pyproject()["project"]["version"]
    result = CliRunner().invoke(app, ["--version"])

    assert project_version == __version__
    assert installed_version("agentguard") == __version__
    assert result.exit_code == 0
    assert result.output.strip() == project_version


def test_release_readiness_documents_and_license_agree() -> None:
    license_text = LICENSE.read_text(encoding="utf-8")
    changelog = CHANGELOG.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    release_doc = RELEASE_DOC.read_text(encoding="utf-8")
    evaluation_doc = EVALUATION_DOC.read_text(encoding="utf-8")

    assert license_text.startswith("MIT License\n")
    assert "Copyright (c) 2026 Richin Mrudul" in license_text
    assert "## Unreleased" in changelog
    assert "## v0.2.0 - Release Candidate" in changelog
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
    assert "release_readiness.py" in release_doc

    forbidden_publish_commands = (
        "twine upload",
        "uv publish",
        "hatch publish",
        "flit publish",
        "poetry publish",
    )
    assert not any(command in release_doc for command in forbidden_publish_commands)
    for command in (
        "git switch main",
        "git pull --ff-only origin main",
        ".venv/bin/python scripts/showcase_metrics.py --check",
        'git tag -a v0.2.0 -m "AgentGuard v0.2.0"',
        "git push origin v0.2.0",
        "gh release create v0.2.0",
    ):
        assert command in release_doc
    assert "AgentGuard v0.2.0 has been tagged" in readme
    assert "no v0.2.0 GitHub release or PyPI publication" in readme
    assert "does not publish a package, create a git tag" in release_doc
    assert "No command in this\nrepository performs those operations automatically." in release_doc


def test_release_readiness_script_and_artifacts_are_valid() -> None:
    assert READINESS_SCRIPT.exists()
    artifact = json_load(READINESS_JSON)
    markdown = READINESS_MD.read_text(encoding="utf-8")
    generated = build_readiness_summary()

    assert artifact == generated
    assert artifact["schema"] == "agentguard.release-readiness"
    assert artifact["schema_version"] == 1
    assert artifact["release"] == "v0.2.0"
    assert artifact["recommendation"] == "ready with caveats"
    assert artifact["package_metadata"]["version"] == __version__
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
    assert "Recommendation: **ready with caveats**" in markdown
    assert "PyPI publishing" in markdown


def test_release_candidate_artifacts_are_valid() -> None:
    artifact = json_load(RELEASE_CANDIDATE_JSON)
    markdown = RELEASE_CANDIDATE_MD.read_text(encoding="utf-8")
    generated = build_release_candidate_summary()

    assert artifact == generated
    assert artifact["schema"] == "agentguard.release-candidate"
    assert artifact["schema_version"] == 1
    assert artifact["release"] == "v0.2.0"
    assert artifact["status"] == "release candidate"
    assert artifact["recommendation"] == "ready to tag after merge with caveats"
    assert artifact["package_metadata"]["version"] == __version__
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
    assert "git tag creation" in artifact["not_performed_by_this_pr"]
    for command in (
        "git switch main",
        "git pull --ff-only origin main",
        "bash scripts/build_release.sh",
        ".venv/bin/python scripts/showcase_metrics.py --check",
        'git tag -a v0.2.0 -m "AgentGuard v0.2.0"',
        "git push origin v0.2.0",
    ):
        assert command in artifact["post_merge_release_commands"]
        assert command in markdown
    assert artifact["adversarial_metrics"]["total_scenarios"] == 10
    assert "v0.2.0 has not been tagged" in markdown
    assert "gh release create v0.2.0" in markdown
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
    assert "actions/upload-artifact@v4" in str(jobs["package"])
    assert "scripts/build_release.sh" in str(jobs["package"])
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
