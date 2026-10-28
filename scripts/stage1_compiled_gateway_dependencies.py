#!/usr/bin/env python3
"""Emit bounded Linux Rust dependency/license inventory without local paths."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "runtime-images/stage1-metering-rust/Cargo.lock"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
ALLOWED_LICENSES = frozenset({
    "MIT", "MIT OR Apache-2.0", "MIT/Apache-2.0", "Unlicense OR MIT",
    "Apache-2.0 AND ISC", "Apache-2.0 OR ISC OR MIT", "Apache-2.0 OR MIT", "ISC",
    "BSD-3-Clause", "(MIT OR Apache-2.0) AND Unicode-3.0",
    "CDLA-Permissive-2.0",
})


def inventory(metadata: dict[str, object], lock: dict[str, object]) -> dict[str, object]:
    packages = metadata.get("packages")
    locked = lock.get("package")
    if not isinstance(packages, list) or not isinstance(locked, list):
        raise ValueError("Cargo metadata or lockfile lacks package rows")
    locked_by_id = {
        (item["name"], item["version"]): item for item in locked
        if isinstance(item, dict)
    }
    records = []
    seen = set()
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("Cargo package row is malformed")
        name, version = package.get("name"), package.get("version")
        license_id, source = package.get("license"), package.get("source")
        if (not isinstance(name, str) or not isinstance(version, str)
                or (name, version) in seen or license_id not in ALLOWED_LICENSES):
            raise ValueError("Cargo package identity or license is unreviewed")
        seen.add((name, version))
        locked_package = locked_by_id.get((name, version))
        if locked_package is None or locked_package.get("source") != source:
            raise ValueError("Cargo metadata and lockfile source differ")
        if source not in (REGISTRY, None):
            raise ValueError("Cargo source is not the reviewed crates.io registry")
        checksum = locked_package.get("checksum")
        if source == REGISTRY:
            if (not isinstance(checksum, str) or len(checksum) != 64
                    or any(character not in "0123456789abcdef" for character in checksum)):
                raise ValueError("Cargo registry package lacks a SHA-256 checksum")
        elif name != "agentguard-stage1-metering-gateway":
            raise ValueError("unreviewed local Cargo package")
        manifest = package.get("manifest_path")
        if not isinstance(manifest, str):
            raise ValueError("Cargo package source path is missing")
        root = Path(manifest).parent
        notices = []
        for item in sorted(root.iterdir()):
            if not item.is_file() or not item.name.upper().startswith(
                ("LICENSE", "COPYING", "NOTICE", "COPYRIGHT")
            ):
                continue
            if item.stat().st_size > 128 * 1024:
                raise ValueError("license or notice exceeds bound")
            notices.append({
                "name": item.name,
                "sha256": "sha256:" + hashlib.sha256(item.read_bytes()).hexdigest(),
            })
        records.append({
            "name": name, "version": version, "license": license_id,
            "source": "crates.io" if source else "repository",
            "checksum": "sha256:" + checksum if checksum else None,
            "notices": notices,
        })
    records.sort(key=lambda item: (item["name"], item["version"]))
    if len(records) < 10 or len(records) > 128:
        raise ValueError("Cargo dependency count differs from bounded review")
    return {
        "schema": "agentguard.stage1-compiled-gateway-source-sbom",
        "schema_version": 1,
        "target": "x86_64-unknown-linux-musl",
        "packages": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        metadata = json.load(sys.stdin)
        lock = tomllib.loads(LOCK.read_text(encoding="utf-8"))
        output = inventory(metadata, lock)
        args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"compiled dependency inventory rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
