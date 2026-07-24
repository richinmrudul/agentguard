#!/usr/bin/env python3
from __future__ import annotations

import email.parser
import json
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path


REQUIRED_PACKAGE_MEMBERS = {
    "agentguard/__init__.py",
    "agentguard/cli/main.py",
    "agentguard/benchmarks/registry.py",
    "agentguard/core/orchestrator.py",
}
FORBIDDEN_PREFIXES = (
    ".agentguard/",
    ".github/",
    ".pytest_cache/",
    ".ruff_cache/",
    ".venv/",
    "build/",
    "dist/",
    "docs/",
    "examples/",
    "scripts/",
    "tests/",
)
FORBIDDEN_NAMES = {
    ".DS_Store",
    ".env",
    "history.db",
}
EXPECTED_NAME = "agentguard"
EXPECTED_LICENSE_FILE = "LICENSE"
REQUIRED_RELEASE_READINESS_ARTIFACTS = (
    "docs/results/release-readiness-v0.2.json",
    "docs/results/release-readiness-v0.2.md",
    "docs/results/release-candidate-v0.2.0.json",
    "docs/results/release-candidate-v0.2.0.md",
    "docs/results/adversarial-metrics.json",
    "docs/results/adversarial-pack-summary.json",
)
FORBIDDEN_RELEASE_MARKERS = (
    "AGENTGUARD_FAKE_TOKEN_EXAMPLE",
    "AGENTGUARD_SHOWCASE_SECRET",
    "AGENTGUARD_SECRET",
    "diff --git",
    "/Users/",
    "/private/",
    "/tmp/",
    "HOME=",
    "TMPDIR=",
    "javascript:",
    "file:",
)


def project_version(root: Path) -> str:
    in_project = False
    for line in (root / "pyproject.toml").read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped == "[project]":
            in_project = True
            continue
        if in_project and stripped.startswith("["):
            break
        if in_project and stripped.startswith("version"):
            _, raw_value = stripped.split("=", 1)
            version = raw_value.strip().strip('"')
            if version:
                return version
    raise AssertionError("pyproject.toml is missing project.version")


def validate_version_tag(root: Path, version: str) -> None:
    tag = f"v{version}"
    tagged_commit = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"refs/tags/{tag}^{{commit}}"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if tagged_commit.returncode == 1:
        return
    if tagged_commit.returncode != 0:
        raise AssertionError(f"Could not inspect release tag {tag}.")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tagged = tagged_commit.stdout.strip()
    if tagged != head:
        raise AssertionError(
            f"Version {version} is already tagged at {tagged}; "
            f"current HEAD is {head}."
        )


def _wheel_members(path: Path) -> set[str]:
    with zipfile.ZipFile(path) as archive:
        return set(archive.namelist())


def _sdist_members(path: Path) -> set[str]:
    with tarfile.open(path, "r:gz") as archive:
        names = archive.getnames()
    normalized = set()
    for name in names:
        parts = Path(name).parts
        if len(parts) > 1:
            normalized.add(Path(*parts[1:]).as_posix())
        else:
            normalized.add(name)
    return normalized


def _metadata_from_wheel(path: Path) -> email.message.Message:
    with zipfile.ZipFile(path) as archive:
        metadata_name = next(
            name
            for name in archive.namelist()
            if name.endswith(".dist-info/METADATA")
        )
        return email.parser.Parser().parsestr(
            archive.read(metadata_name).decode("utf-8")
        )


def _metadata_from_sdist(path: Path) -> email.message.Message:
    with tarfile.open(path, "r:gz") as archive:
        pkg_info_name = next(
            name for name in archive.getnames() if name.endswith("/PKG-INFO")
        )
        pkg_info = archive.extractfile(pkg_info_name)
        if pkg_info is None:
            raise AssertionError(f"Could not read {pkg_info_name}")
        return email.parser.Parser().parsestr(pkg_info.read().decode("utf-8"))


def _assert_required_members(label: str, members: set[str]) -> None:
    missing = sorted(REQUIRED_PACKAGE_MEMBERS - members)
    if missing:
        raise AssertionError(f"{label} missing required package files: {missing}")


def _assert_forbidden_members(label: str, members: set[str]) -> None:
    forbidden = []
    for member in members:
        path = Path(member)
        if member.startswith(FORBIDDEN_PREFIXES) or path.name in FORBIDDEN_NAMES:
            forbidden.append(member)
    if forbidden:
        raise AssertionError(f"{label} contains forbidden files: {sorted(forbidden)}")


def _assert_metadata(label: str, metadata: email.message.Message) -> str:
    name = metadata.get("Name")
    version = metadata.get("Version")
    requires_python = metadata.get("Requires-Python")
    license_files = metadata.get_all("License-File", [])
    if name != EXPECTED_NAME:
        raise AssertionError(f"{label} has unexpected name: {name!r}")
    if not version:
        raise AssertionError(f"{label} is missing Version metadata")
    if requires_python != ">=3.9":
        raise AssertionError(
            f"{label} has unexpected Requires-Python: {requires_python!r}"
        )
    if EXPECTED_LICENSE_FILE not in license_files:
        raise AssertionError(
            f"{label} is missing License-File metadata: {license_files!r}"
        )
    return version


def validate_artifacts(wheel_path: Path, sdist_path: Path) -> None:
    wheel_members = _wheel_members(wheel_path)
    sdist_members = _sdist_members(sdist_path)

    _assert_required_members("wheel", wheel_members)
    _assert_required_members("sdist", sdist_members)
    _assert_forbidden_members("wheel", wheel_members)
    _assert_forbidden_members("sdist", sdist_members)
    if not any(member.endswith("/LICENSE") for member in wheel_members):
        raise AssertionError("wheel is missing the MIT license file")
    if EXPECTED_LICENSE_FILE not in sdist_members:
        raise AssertionError("sdist is missing the MIT license file")

    wheel_version = _assert_metadata("wheel", _metadata_from_wheel(wheel_path))
    sdist_version = _assert_metadata("sdist", _metadata_from_sdist(sdist_path))
    if wheel_version != sdist_version:
        raise AssertionError(
            f"wheel/sdist version mismatch: {wheel_version} != {sdist_version}"
        )


def validate_release_readiness(root: Path) -> None:
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    if "## v0.2.0 - 2026-07-17" not in changelog:
        raise AssertionError("CHANGELOG.md is missing the v0.2.0 section")
    combined = []
    for relative_path in REQUIRED_RELEASE_READINESS_ARTIFACTS:
        path = root / relative_path
        if not path.is_file():
            raise AssertionError(f"Missing release readiness artifact: {relative_path}")
        text = path.read_text(encoding="utf-8")
        combined.append(text)
        if path.suffix == ".json":
            data = json.loads(text)
            if not isinstance(data, dict):
                raise AssertionError(f"{relative_path} must contain a JSON object")
    release_readiness = root / "docs/results/release-readiness-v0.2.json"
    readiness = json.loads(release_readiness.read_text(encoding="utf-8"))
    if readiness.get("release") != "v0.2.0":
        raise AssertionError("release-readiness-v0.2.json has wrong release")
    if readiness.get("package_metadata", {}).get("version") != "0.2.0":
        raise AssertionError("release-readiness-v0.2.json has wrong package version")
    if readiness.get("recommendation") != "released":
        raise AssertionError("release-readiness-v0.2.json has wrong release status")
    for marker in FORBIDDEN_RELEASE_MARKERS:
        if marker in "\n".join(combined):
            raise AssertionError(f"Release readiness artifacts contain {marker!r}")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    if sys.argv[1:] == ["--check-version-tag"]:
        validate_version_tag(root, project_version(root))
        print("Release version tag is consistent with HEAD.")
        return 0
    if len(sys.argv) == 1:
        validate_release_readiness(root)
        print("Release readiness artifacts validated.")
        return 0
    if len(sys.argv) != 3:
        print(
            "Usage: validate_release_artifacts.py [WHEEL SDIST]",
            file=sys.stderr,
        )
        return 2
    validate_artifacts(Path(sys.argv[1]), Path(sys.argv[2]))
    print("Release artifacts validated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
