#!/usr/bin/env python3
from __future__ import annotations

import email.parser
import json
import re
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
EXPECTED_NAME = "agentguard-evals"
EXPECTED_NORMALIZED_NAME = "agentguard_evals"
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
CURRENT_STATE_HEADINGS = (
    "current",
    "quickstart",
    "installation",
    "proof",
    "release status",
)
HISTORICAL_HEADINGS = (
    "changelog",
    "history",
    "historical",
    "previous",
    "completed",
)
CURRENT_RELEASE_CLAIMS = (
    "current release",
    "current published",
    "current production",
    "latest release",
    "production pypi continues to serve",
)
UNPUBLISHED_CLAIMS = (
    "not published",
    "has not been published",
    "have not been published",
    "not yet published",
    "unpublished",
    "pypi publication remains deferred",
    "pypi publishing remains deferred",
    "production pypi continues to serve",
)
RELEASE_CANDIDATE_CLAIMS = (
    "release candidate",
    "source candidate",
    "pre-release candidate",
)
SHIPPED_FEATURE_TERMS = (
    "baseline-aware",
    "ci policy",
    "go module",
    "json schema",
    "node.js",
    "policy preset",
    "project initialization",
)
VERSION_RE = re.compile(r"\bv?(\d+\.\d+\.\d+)\b")


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


def validate_ordinary_package_context(root: Path) -> None:
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    package_init = (root / "agentguard/__init__.py").read_text(encoding="utf-8")
    package_version_match = re.search(
        r'(?m)^__version__\s*=\s*"([^"]+)"\s*$',
        package_init,
    )
    if package_version_match is None:
        raise AssertionError("agentguard.__version__ is missing")
    declared_version = project_version(root)
    package_version = package_version_match.group(1)
    if package_version != declared_version:
        raise AssertionError(
            "Package version mismatch: "
            f"pyproject={declared_version!r}, agentguard={package_version!r}"
        )
    if not re.search(
        rf'(?m)^name\s*=\s*"{re.escape(EXPECTED_NAME)}"\s*$',
        pyproject,
    ):
        raise AssertionError(
            f"pyproject.toml must declare distribution {EXPECTED_NAME!r}"
        )
    if not re.search(
        r'(?m)^agentguard\s*=\s*"agentguard\.cli\.main:app"\s*$',
        pyproject,
    ):
        raise AssertionError(
            "pyproject.toml must preserve the agentguard console entry point"
        )


def validate_strict_release_tag(root: Path, version: str) -> None:
    tag = f"v{version}"
    tag_type = subprocess.run(
        ["git", "cat-file", "-t", f"refs/tags/{tag}"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if tag_type.returncode != 0:
        raise AssertionError(f"Strict release tag {tag} does not exist.")
    if tag_type.stdout.strip() != "tag":
        raise AssertionError(f"Strict release tag {tag} must be annotated.")
    tagged_commit = subprocess.run(
        ["git", "rev-parse", f"refs/tags/{tag}^{{commit}}"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if tagged_commit != head:
        raise AssertionError(
            f"Strict release tag {tag} points to {tagged_commit}; "
            f"current HEAD is {head}."
        )


def validate_strict_release_context(root: Path) -> None:
    validate_ordinary_package_context(root)
    validate_strict_release_tag(root, project_version(root))


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
    _assert_long_description_release_state(label, version, metadata.get_payload())
    return version


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _section_heading(line: str) -> tuple[int, str] | None:
    match = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
    if match is None:
        return None
    return len(match.group(1)), match.group(2).strip().lower()


def _iter_release_state_sections(text: str) -> list[tuple[str, str, bool, bool]]:
    sections = []
    heading = ""
    lines: list[str] = []
    historical = False
    current = False
    heading_stack: list[tuple[int, bool, bool]] = []
    for line in text.splitlines():
        next_heading = _section_heading(line)
        if next_heading is not None:
            if lines:
                sections.append((heading, "\n".join(lines), historical, current))
            level, heading = next_heading
            lines = []
            heading_stack = [
                entry for entry in heading_stack if entry[0] < level
            ]
            heading_historical = any(
                marker in heading for marker in HISTORICAL_HEADINGS
            )
            heading_current = any(marker in heading for marker in CURRENT_STATE_HEADINGS)
            heading_stack.append((level, heading_historical, heading_current))
            historical = any(entry[1] for entry in heading_stack)
            current = any(entry[2] for entry in heading_stack)
            continue
        lines.append(line)
    if lines:
        sections.append((heading, "\n".join(lines), historical, current))
    return sections


def _iter_sentences(text: str) -> list[str]:
    return [
        sentence.strip()
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", text)
        if sentence.strip()
    ]


def _normalize_claim_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).lower()


def _assert_long_description_release_state(
    label: str,
    version: str,
    description: object,
) -> None:
    if not isinstance(description, str):
        raise AssertionError(f"{label} is missing long description metadata")

    current_key = _version_key(version)
    for _, section, is_historical, is_current in _iter_release_state_sections(
        description
    ):
        if is_historical:
            continue
        section_claim = _normalize_claim_text(section)
        current_context = is_current or any(
            marker in section_claim for marker in CURRENT_RELEASE_CLAIMS
        )
        for sentence in _iter_sentences(section):
            claim = _normalize_claim_text(sentence)
            versions = VERSION_RE.findall(sentence)
            older_versions = [
                candidate
                for candidate in versions
                if _version_key(candidate) < current_key
            ]

            if current_context and older_versions and re.search(
                r"docs/results/(?:release-candidate|release-readiness|release)-v"
                r"\d+\.\d+(?:\.\d+)?\.(?:md|json)",
                sentence,
            ):
                raise AssertionError(
                    f"{label} long description directs current release evidence "
                    f"to stale version {older_versions[0]}"
                )

            if version in versions and any(
                marker in claim for marker in UNPUBLISHED_CLAIMS
            ):
                raise AssertionError(
                    f"{label} long description calls {version} unpublished"
                )

            if version in versions and any(
                marker in claim for marker in RELEASE_CANDIDATE_CLAIMS
            ):
                raise AssertionError(
                    f"{label} long description calls {version} a release candidate"
                )

            if any(marker in claim for marker in RELEASE_CANDIDATE_CLAIMS) and any(
                feature in claim for feature in SHIPPED_FEATURE_TERMS
            ):
                raise AssertionError(
                    f"{label} long description describes a shipped feature "
                    "as a release candidate"
                )

            if older_versions and any(
                marker in claim for marker in CURRENT_RELEASE_CLAIMS
            ):
                raise AssertionError(
                    f"{label} long description calls older release "
                    f"{older_versions[0]} current while publishing {version}"
                )


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
    expected_wheel = f"{EXPECTED_NORMALIZED_NAME}-{wheel_version}-py3-none-any.whl"
    expected_sdist = f"{EXPECTED_NORMALIZED_NAME}-{wheel_version}.tar.gz"
    if wheel_path.name != expected_wheel:
        raise AssertionError(
            f"wheel has unexpected filename: {wheel_path.name!r}"
        )
    if sdist_path.name != expected_sdist:
        raise AssertionError(
            f"sdist has unexpected filename: {sdist_path.name!r}"
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
    if sys.argv[1:] == ["--ordinary-ci"]:
        validate_ordinary_package_context(root)
        print("Ordinary package context validated without binding HEAD to a tag.")
        return 0
    if sys.argv[1:] == ["--strict-release-tag"]:
        validate_strict_release_context(root)
        print("Strict package context and release tag validated.")
        return 0
    if len(sys.argv) == 1:
        validate_release_readiness(root)
        print("Release readiness artifacts validated.")
        return 0
    if len(sys.argv) != 3:
        print(
            "Usage: validate_release_artifacts.py "
            "[--ordinary-ci | --strict-release-tag | WHEEL SDIST]",
            file=sys.stderr,
        )
        return 2
    validate_artifacts(Path(sys.argv[1]), Path(sys.argv[2]))
    print("Release artifacts validated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
