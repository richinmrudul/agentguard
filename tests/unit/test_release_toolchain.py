from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from scripts.validate_release_toolchain import (
    EXPECTED_LOCK,
    LOCK_RELATIVE_PATH,
    build_evidence,
    validate_lock,
    validate_installed,
)


ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = ROOT / LOCK_RELATIVE_PATH
WORKFLOW_PATH = ROOT / ".github/workflows/publish.yml"
BUILD_SCRIPT = ROOT / "scripts/build_release.sh"
PACKAGE_SMOKE = ROOT / "scripts/package_smoke.sh"
RELEASE_DOC = ROOT / "docs/release.md"
RELEASE_CHECKLIST = ROOT / "docs/release-checklist.md"


def _copy_lock(tmp_path: Path) -> Path:
    copied = tmp_path / "release-build-toolchain.txt"
    shutil.copyfile(LOCK_PATH, copied)
    return copied


def test_release_toolchain_lock_is_exact_reviewed_set() -> None:
    requirements = validate_lock(LOCK_PATH)

    assert set(requirements) == set(EXPECTED_LOCK)
    for name, requirement in requirements.items():
        assert requirement.version == EXPECTED_LOCK[name]["version"]
        assert requirement.sha256 == EXPECTED_LOCK[name]["hash"]
        assert re.fullmatch(r"[0-9a-f]{64}", requirement.sha256)


def test_release_toolchain_lock_requires_hashes_and_binary_artifacts() -> None:
    lock = LOCK_PATH.read_text(encoding="utf-8")

    assert "--require-hashes" in lock
    assert "--only-binary=:all:" in lock
    assert all(
        "--hash=sha256:" in line
        for line in lock.splitlines()
        if line and not line.startswith(("#", "--"))
    )


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ("build==1.3.0", "build>=1.3.0,<2.0.0", "exactly pinned"),
        (" --hash=sha256:7145", " # hash removed", "exactly one sha256 hash"),
        ("setuptools==80.9.0", "setuptools==80.10.0", "version mismatch"),
        ("062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922", "f" * 64, "hash mismatch"),
    ],
)
def test_release_toolchain_lock_rejects_mutation(
    tmp_path: Path,
    old: str,
    new: str,
    message: str,
) -> None:
    copied = _copy_lock(tmp_path)
    copied.write_text(
        copied.read_text(encoding="utf-8").replace(old, new),
        encoding="utf-8",
    )

    with pytest.raises(AssertionError, match=message):
        validate_lock(copied)


def test_release_toolchain_lock_rejects_missing_or_extra_entries(
    tmp_path: Path,
) -> None:
    copied = _copy_lock(tmp_path)
    lines = copied.read_text(encoding="utf-8").splitlines()
    copied.write_text(
        "\n".join(line for line in lines if not line.startswith("tomli=="))
        + "\nextra-build-tool==1.0.0 --hash=sha256:"
        + ("a" * 64)
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(AssertionError, match="missing=\\['tomli'\\].*extra"):
        validate_lock(copied)


def test_release_toolchain_evidence_is_deterministic() -> None:
    requirements = validate_lock(LOCK_PATH)

    first = build_evidence(ROOT, LOCK_PATH, requirements)
    second = build_evidence(ROOT, LOCK_PATH, requirements)

    assert first == second
    assert first["schema"] == "agentguard.release-build-toolchain"
    assert first["scope"] == "authoritative Linux release build environment"
    assert first["lock_file"] == LOCK_RELATIVE_PATH.as_posix()
    assert re.fullmatch(r"[0-9a-f]{64}", first["lock_sha256"])
    assert first["runner"] == {
        "system": "Linux",
        "github_actions_runs_on": "ubuntu-latest",
        "workflow": ".github/workflows/publish.yml",
    }
    assert first["python"] == {
        "implementation": first["python"]["implementation"],
        "version": first["python"]["version"],
    }
    assert first["pip"] == {"version": first["pip"]["version"]}
    assert "locked_requirements" in first
    assert "active_requirements" in first


def test_release_toolchain_evidence_excludes_paths_and_ambient_platform() -> None:
    requirements = validate_lock(LOCK_PATH)
    evidence = json.dumps(
        build_evidence(ROOT, LOCK_PATH, requirements),
        sort_keys=True,
    )

    assert str(ROOT) not in evidence
    assert sys.executable not in evidence
    assert "site-packages" not in evidence
    assert "executable" not in evidence
    assert "platform" not in evidence


def test_release_toolchain_validator_cli_emits_json_evidence(tmp_path: Path) -> None:
    output = tmp_path / "toolchain.json"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/validate_release_toolchain.py",
            "--check-installed",
            "--emit-evidence",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["schema"] == "agentguard.release-build-toolchain"
    assert data["locked_requirements"][0]["name"] == "build"
    assert str(output) not in result.stdout
    assert "executable" not in json.dumps(data, sort_keys=True)


def test_release_toolchain_installed_check_rejects_missing_required_package() -> None:
    requirements = validate_lock(LOCK_PATH)
    build_requirement = requirements["build"]
    missing_build = type(build_requirement)(
        name=f"missing-{build_requirement.name}",
        version="99.99.99",
        marker=build_requirement.marker,
        sha256=build_requirement.sha256,
    )

    with pytest.raises(AssertionError, match="is not installed: missing-build"):
        validate_installed({missing_build.name: missing_build})


def test_publish_workflow_installs_reviewed_hashed_toolchain_lock() -> None:
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    source = WORKFLOW_PATH.read_text(encoding="utf-8")
    build_steps = workflow["jobs"]["build"]["steps"]

    install_step = next(
        step for step in build_steps if step["name"] == "Install build dependencies"
    )
    assert "scripts/validate_release_toolchain.py" in install_step["run"]
    assert "--require-hashes" in install_step["run"]
    assert "--only-binary=:all:" in install_step["run"]
    assert "-r requirements/release-build-toolchain.txt" in install_step["run"]
    assert "build>=1.2.0" not in source
    assert "setuptools>=77" not in source


def test_build_and_smoke_scripts_cannot_fall_back_to_unbounded_installs() -> None:
    build_script = BUILD_SCRIPT.read_text(encoding="utf-8")
    smoke_script = PACKAGE_SMOKE.read_text(encoding="utf-8")
    combined = f"{build_script}\n{smoke_script}"

    assert "validate_release_toolchain.py" in build_script
    assert "release-build-toolchain.json" in build_script
    assert "requirements/release-build-toolchain.txt" in smoke_script
    assert "--require-hashes" in smoke_script
    assert "--only-binary=:all:" in smoke_script
    assert "pip install build" not in combined
    assert '"setuptools>=77"' not in combined
    assert "build>=1.2.0" not in combined


def test_release_docs_describe_controlled_toolchain_lock_update() -> None:
    combined = (
        RELEASE_DOC.read_text(encoding="utf-8")
        + "\n"
        + RELEASE_CHECKLIST.read_text(encoding="utf-8")
    )

    for required in (
        "release-build-toolchain.txt",
        "validate_release_toolchain.py",
        "--require-hashes",
        "reviewed lock",
        "release-build-toolchain.json",
        "controlled toolchain-lock update",
    ):
        assert required in combined
