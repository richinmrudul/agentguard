import os
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"
COVERAGE_SCRIPT = ROOT / "scripts/coverage.sh"
CI_WORKFLOW = ROOT / ".github/workflows/ci.yml"
README = ROOT / "README.md"
TESTING_DOC = ROOT / "docs/testing.md"


def _load_pyproject() -> dict:
    if sys.version_info >= (3, 11):
        import tomllib

        return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))

    import tomli

    return tomli.loads(PYPROJECT.read_text(encoding="utf-8"))


def test_coverage_configuration_measures_source_and_branches() -> None:
    coverage = _load_pyproject()["tool"]["coverage"]

    assert coverage["run"]["branch"] is True
    assert coverage["run"]["source"] == ["agentguard"]
    assert coverage["report"]["fail_under"] == 88
    assert coverage["report"]["show_missing"] is True
    assert "omit" not in coverage["run"]
    assert "omit" not in coverage["report"]


def test_coverage_script_is_portable_strict_and_executable() -> None:
    script = COVERAGE_SCRIPT.read_text(encoding="utf-8")

    assert os.access(COVERAGE_SCRIPT, os.X_OK)
    assert "set -euo pipefail" in script
    assert 'ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)' in script
    assert 'PYTHON_BIN=$(command -v "$PYTHON_BIN")' in script
    assert 'cd "$ROOT_DIR"' in script
    assert "not docker and not package" in script
    assert "--full" in script
    assert "--html" in script
    assert "coverage report --fail-under=" in script


def test_ci_enforces_coverage_and_uploads_local_artifacts() -> None:
    workflow = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
    coverage_job = workflow["jobs"]["coverage"]
    serialized = str(coverage_job)

    setup_step = next(
        step
        for step in coverage_job["steps"]
        if step.get("uses") == "actions/setup-python@v5"
    )
    assert setup_step["with"]["python-version"] == "3.11"
    assert "scripts/coverage.sh --html" in serialized
    assert "actions/upload-artifact@v4" in serialized
    assert "coverage/coverage.xml" in serialized
    assert "coverage/html/" in serialized
    assert "codecov" not in serialized.lower()
    assert "token" not in serialized.lower()


def test_testing_documentation_references_existing_commands_and_files() -> None:
    readme = README.read_text(encoding="utf-8")
    testing = TESTING_DOC.read_text(encoding="utf-8")

    assert "[Testing and quality](docs/testing.md)" in readme
    assert "bash scripts/coverage.sh" in readme
    assert "bash scripts/coverage.sh" in testing
    assert COVERAGE_SCRIPT.exists()
    assert (ROOT / "docs/benchmarks.md").exists()
    assert (ROOT / "docs/detection-quality.md").exists()
