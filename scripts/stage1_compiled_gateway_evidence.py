#!/usr/bin/env python3
"""Validate two independently built scratch gateway candidates; never publish."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentguard.evaluation.runtime_images import (  # noqa: E402
    RuntimeImageError,
    canonical_json_digest,
    canonical_rootfs_digest,
    canonical_runtime_config,
)
from scripts.stage1_publication_manifest import normalized_sbom_package_rows  # noqa: E402


BUILDER = (
    "docker.io/library/rust:1.95.0-alpine3.22@"
    "sha256:2805e96db5234c9cfaf7ecb50f488693dab84d28ad30b6290cc1b707a18bf775"
)
SOURCE_FILES = [
    Path("runtime-images/stage1-metering-rust/Cargo.toml"),
    Path("runtime-images/stage1-metering-rust/Cargo.lock"),
    Path("runtime-images/stage1-metering-rust/rust-toolchain.toml"),
    Path("runtime-images/stage1-metering-rust/Dockerfile"),
    Path("agentguard/evaluation/stage1_pricing_v2.json"),
]


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise RuntimeImageError(f"expected JSON object: {path.name}")
    return document


def _sha(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _source_digest() -> str:
    files = SOURCE_FILES + sorted(Path("runtime-images/stage1-metering-rust/src").glob("*.rs"))
    return canonical_json_digest({str(path): _sha(path) for path in files})


def _rootfs(rootfs: Path) -> dict[str, object]:
    with tarfile.open(rootfs, "r:*") as archive:
        names = {item.name.lstrip("./"): item for item in archive.getmembers()}
        expected = {"stage1-metering-gateway"}
        files = {name for name, item in names.items() if item.isfile()}
        if files != expected or any(item.issym() or item.islnk() for item in names.values()):
            raise RuntimeImageError("scratch gateway contains unexpected runtime files or links")
        binary = archive.extractfile(names["stage1-metering-gateway"])
        if binary is None:
            raise RuntimeImageError("compiled gateway binary is absent")
        binary_digest = "sha256:" + hashlib.sha256(binary.read()).hexdigest()
        for item in names.values():
            if item.isfile() and item.mode & 0o022:
                raise RuntimeImageError("scratch runtime file is group/world writable")
    return {
        "rootfs_digest": canonical_rootfs_digest(rootfs),
        "binary_digest": binary_digest,
        "runtime_files": sorted(files),
    }


def _findings(document: dict[str, object]) -> list[dict[str, str]]:
    results = document.get("Results")
    if not isinstance(results, list):
        raise RuntimeImageError("raw Trivy results are missing")
    findings = []
    for result in results:
        if not isinstance(result, dict):
            raise RuntimeImageError("Trivy result is malformed")
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise RuntimeImageError("Trivy vulnerability list is malformed")
        for item in vulnerabilities:
            if not isinstance(item, dict):
                raise RuntimeImageError("Trivy finding is malformed")
            finding = {
                "type": str(result.get("Type", "")),
                "cve": str(item.get("VulnerabilityID", "")),
                "severity": str(item.get("Severity", "")),
                "package": str(item.get("PkgName", "")),
                "installed": str(item.get("InstalledVersion", "")),
                "fixed": str(item.get("FixedVersion", "")),
            }
            if not finding["cve"] or not finding["package"] or finding["severity"] not in {"HIGH", "CRITICAL"}:
                raise RuntimeImageError("Trivy finding is unbound or severity differs")
            findings.append(finding)
    return sorted(findings, key=lambda item: tuple(item.values()))


def _candidate(root: Path, build: str, source: str) -> dict[str, object]:
    inspect = json.loads((root / f"gateway-{build}.inspect.json").read_text(encoding="utf-8"))
    config = canonical_runtime_config(inspect)
    if config["architecture"] != "amd64" or config["os"] != "linux" or config["user"] != "65532:65532":
        raise RuntimeImageError("compiled runtime platform or user differs")
    if config["entrypoint"] != ["/stage1-metering-gateway"] or config["working_dir"] != "/":
        raise RuntimeImageError("compiled runtime entrypoint or workdir differs")
    if config["env"] or config["volumes"] or config["cmd"]:
        raise RuntimeImageError("compiled runtime contains ambient environment, volume, or command")
    rootfs = _rootfs(root / f"gateway-{build}.rootfs.tar")
    sbom = _read_json(root / f"gateway-{build}.sbom.json")
    rows = normalized_sbom_package_rows(sbom)
    findings = _findings(_read_json(root / f"gateway-{build}.trivy.json"))
    identity = canonical_json_digest({
        "schema": "agentguard.stage1-compiled-gateway-canonical-identity",
        "schema_version": 1,
        "platform": "linux/amd64",
        "final_base": "scratch",
        "builder_base": BUILDER,
        "source_digest": source,
        "rootfs_digest": rootfs["rootfs_digest"],
        "runtime_config_digest": canonical_json_digest(config),
    })
    return {
        "identity": identity,
        "source_digest": source,
        "builder_base": BUILDER,
        "rootfs": rootfs,
        "runtime_config": config,
        "sbom_rows_digest": canonical_json_digest(rows),
        "sbom_rows": rows,
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    arguments = parser.parse_args()
    root = arguments.evidence
    try:
        source = _source_digest()
        first = _candidate(root, "a", source)
        second = _candidate(root, "b", source)
        for field in ("identity", "rootfs", "runtime_config", "sbom_rows_digest", "sbom_rows", "findings"):
            if first[field] != second[field]:
                raise RuntimeImageError(f"independent compiled builds differ for {field}")
        report = {
            "schema": "agentguard.stage1-compiled-gateway-security-evidence",
            "schema_version": 1,
            "candidate": first,
            "reproducible": True,
            "sbom_package_count": len(first["sbom_rows"]),
            "high_critical_count": len(first["findings"]),
        }
        (root / "compiled-gateway-review.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8",
        )
        print(json.dumps({
            "identity": first["identity"],
            "binary_digest": first["rootfs"]["binary_digest"],
            "sbom_package_count": len(first["sbom_rows"]),
            "high_critical_count": len(first["findings"]),
        }, sort_keys=True))
        if first["findings"]:
            raise RuntimeImageError("unreviewed HIGH/CRITICAL requires separate review")
    except (OSError, ValueError, KeyError, RuntimeImageError) as error:
        print(f"compiled gateway evidence rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
