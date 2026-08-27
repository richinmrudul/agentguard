#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import re
import sys
from dataclasses import dataclass
from pathlib import Path


LOCK_RELATIVE_PATH = Path("requirements/release-build-toolchain.txt")
EXPECTED_REQUIRE_HASHES = "--require-hashes"
EXPECTED_ONLY_BINARY = "--only-binary=:all:"
AUTHORITATIVE_RUNNER = {
    "system": "Linux",
    "github_actions_runs_on": "ubuntu-latest",
    "workflow": ".github/workflows/publish.yml",
}
EXPECTED_LOCK = {
    "build": {
        "version": "1.3.0",
        "marker": "",
        "hash": "7145f0b5061ba90a1500d60bd1b13ca0a8a4cebdd0cc16ed8adf1c0e739f43b4",
    },
    "setuptools": {
        "version": "80.9.0",
        "marker": "",
        "hash": "062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922",
    },
    "packaging": {
        "version": "25.0",
        "marker": "",
        "hash": "29572ef2b1f17581046b3a2227d5c611fb25ec70ca1ba8554b24b0e69331a484",
    },
    "pyproject-hooks": {
        "version": "1.2.0",
        "marker": "",
        "hash": "9e5c6bfa8dcc30091c74b0cf803c81fdd29d94f01992a7707bc97babb1141913",
    },
    "importlib-metadata": {
        "version": "8.7.1",
        "marker": 'python_full_version < "3.10.2"',
        "hash": "5a1f80bf1daa489495071efbb095d75a634cf28a8bc299581244063b53176151",
    },
    "tomli": {
        "version": "2.4.1",
        "marker": 'python_version < "3.11"',
        "hash": "0d85819802132122da43cb86656f8d1f8c6587d54ae7dcaf30e90533028b49fe",
    },
    "zipp": {
        "version": "3.23.1",
        "marker": 'python_full_version < "3.10.2"',
        "hash": "0b3596c50a5c700c9cb40ba8d86d9f2cc4807e9bedb06bcdf7fac85633e444dc",
    },
}
REQUIREMENT_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9_.-]+)==(?P<version>[A-Za-z0-9_.!+-]+)"
    r"(?:;\s*(?P<marker>.+?))?\s+--hash=sha256:(?P<hash>[0-9a-f]{64})$"
)
MUTABLE_SPECIFIER_RE = re.compile(r"(?<![<>=!~])(?:>=|<=|~=|!=|>|<|===|\*)")


@dataclass(frozen=True)
class LockedRequirement:
    name: str
    version: str
    marker: str
    sha256: str


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def _marker_applies(marker: str) -> bool:
    if not marker:
        return True
    python_version = ".".join(str(part) for part in sys.version_info[:2])
    python_full_version = platform.python_version()
    if marker == 'python_version < "3.11"':
        return _version_tuple(python_version) < (3, 11)
    if marker == 'python_full_version < "3.10.2"':
        return _version_tuple(python_full_version) < (3, 10, 2)
    raise AssertionError(f"Unsupported release toolchain marker: {marker!r}")


def parse_lock(lock_path: Path, root: Path | None = None) -> dict[str, LockedRequirement]:
    if not lock_path.is_file():
        display_path = _display_path(lock_path, root or lock_path.parent)
        raise AssertionError(f"Missing release build toolchain lock: {display_path}")

    require_hashes = False
    only_binary = False
    requirements: dict[str, LockedRequirement] = {}
    for line_number, raw_line in enumerate(
        lock_path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == EXPECTED_REQUIRE_HASHES:
            require_hashes = True
            continue
        if line == EXPECTED_ONLY_BINARY:
            only_binary = True
            continue
        if line.startswith(("-", "--")):
            raise AssertionError(
                f"Unsupported release toolchain option on line {line_number}: {line}"
            )
        if "://" in line or line.startswith(("-r", "-c")):
            raise AssertionError(
                f"Release toolchain lock line {line_number} must be self-contained"
            )
        requirement_part = line.split("--hash=", 1)[0].split(";", 1)[0]
        if MUTABLE_SPECIFIER_RE.search(requirement_part.replace("==", "")):
            raise AssertionError(
                f"Release toolchain dependency must be exactly pinned on "
                f"line {line_number}: {line}"
            )
        match = REQUIREMENT_RE.fullmatch(line)
        if match is None:
            raise AssertionError(
                f"Release toolchain lock line {line_number} must use "
                "name==version with exactly one sha256 hash"
            )
        name = _normalize_name(match.group("name"))
        if name in requirements:
            raise AssertionError(f"Duplicate release toolchain entry: {name}")
        requirements[name] = LockedRequirement(
            name=name,
            version=match.group("version"),
            marker=(match.group("marker") or "").strip(),
            sha256=match.group("hash"),
        )

    if not require_hashes:
        raise AssertionError("Release toolchain lock must require package hashes")
    if not only_binary:
        raise AssertionError("Release toolchain lock must force binary artifacts")
    return requirements


def validate_lock(
    lock_path: Path,
    root: Path | None = None,
) -> dict[str, LockedRequirement]:
    requirements = parse_lock(lock_path, root)
    expected_names = set(EXPECTED_LOCK)
    actual_names = set(requirements)
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        extra = sorted(actual_names - expected_names)
        raise AssertionError(
            f"Release toolchain lock entry mismatch: missing={missing}, extra={extra}"
        )

    for name, expected in EXPECTED_LOCK.items():
        requirement = requirements[name]
        if requirement.version != expected["version"]:
            raise AssertionError(
                f"Release toolchain version mismatch for {name}: "
                f"{requirement.version} != {expected['version']}"
            )
        if requirement.marker != expected["marker"]:
            raise AssertionError(
                f"Release toolchain marker mismatch for {name}: "
                f"{requirement.marker!r} != {expected['marker']!r}"
            )
        if requirement.sha256 != expected["hash"]:
            raise AssertionError(
                f"Release toolchain hash mismatch for {name}: "
                f"{requirement.sha256} != {expected['hash']}"
            )
    return requirements


def validate_installed(requirements: dict[str, LockedRequirement]) -> None:
    for requirement in requirements.values():
        if not _marker_applies(requirement.marker):
            continue
        try:
            installed_version = importlib.metadata.version(requirement.name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise AssertionError(
                f"Release toolchain dependency is not installed: {requirement.name}"
            ) from exc
        if installed_version != requirement.version:
            raise AssertionError(
                f"Release toolchain dependency {requirement.name} has "
                f"{installed_version}, expected {requirement.version}"
            )


def build_evidence(
    root: Path,
    lock_path: Path,
    requirements: dict[str, LockedRequirement],
) -> dict[str, object]:
    active = [
        {
            "name": requirement.name,
            "version": requirement.version,
            "marker": requirement.marker or None,
            "sha256": requirement.sha256,
            "installed_version": importlib.metadata.version(requirement.name),
        }
        for requirement in sorted(requirements.values(), key=lambda item: item.name)
        if _marker_applies(requirement.marker)
    ]
    locked = [
        {
            "name": requirement.name,
            "version": requirement.version,
            "marker": requirement.marker or None,
            "sha256": requirement.sha256,
        }
        for requirement in sorted(requirements.values(), key=lambda item: item.name)
    ]
    return {
        "schema": "agentguard.release-build-toolchain",
        "schema_version": 1,
        "scope": "authoritative Linux release build environment",
        "lock_file": lock_path.relative_to(root).as_posix(),
        "lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
        "runner": AUTHORITATIVE_RUNNER,
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
        },
        "pip": {"version": importlib.metadata.version("pip")},
        "locked_requirements": locked,
        "active_requirements": active,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=None)
    parser.add_argument("--check-installed", action="store_true")
    parser.add_argument("--emit-evidence", type=Path)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    lock_path = args.lock or root / LOCK_RELATIVE_PATH
    if not lock_path.is_absolute():
        lock_path = root / lock_path
    requirements = validate_lock(lock_path, root)
    if args.check_installed or args.emit_evidence:
        validate_installed(requirements)
    if args.emit_evidence:
        evidence = build_evidence(root, lock_path, requirements)
        args.emit_evidence.parent.mkdir(parents=True, exist_ok=True)
        args.emit_evidence.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print("Release build toolchain evidence written.")
    else:
        print("Release build toolchain lock validated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
