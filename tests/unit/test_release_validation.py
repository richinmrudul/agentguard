import os
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


ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"
BUILD_SCRIPT = ROOT / "scripts/build_release.sh"
VALIDATION_SCRIPT = ROOT / "scripts/validate_release_artifacts.py"
CI_WORKFLOW = ROOT / ".github/workflows/ci.yml"
LICENSE = ROOT / "LICENSE"
CHANGELOG = ROOT / "CHANGELOG.md"
README = ROOT / "README.md"
RELEASE_DOC = ROOT / "docs/release.md"
EVALUATION_DOC = ROOT / "docs/evaluation.md"
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
    assert "## v0.1.0 - Draft" in changelog
    for target in ("LICENSE", "CHANGELOG.md", "docs/release.md"):
        assert f"]({target})" in readme
    assert "no external-agent benchmark results are" in evaluation_doc
    assert "published with v0.1.0" in evaluation_doc

    forbidden_publish_commands = (
        "twine upload",
        "uv publish",
        "hatch publish",
        "flit publish",
        "poetry publish",
        "gh release create",
        "git tag ",
    )
    assert not any(command in release_doc for command in forbidden_publish_commands)


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
