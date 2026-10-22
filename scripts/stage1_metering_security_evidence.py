#!/usr/bin/env python3
"""Summarize two hosted, mock-only metering-gateway candidate builds."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentguard.evaluation.runtime_images import (  # noqa: E402
    GATEWAY_BASE_IMAGE,
    RuntimeImageError,
    canonical_json_digest,
)
from agentguard.evaluation.stage1_live_pricing import pricing_policy_digest  # noqa: E402
from scripts.stage1_publication_manifest import normalized_sbom_package_rows  # noqa: E402


SOURCE_FILES = (
    "runtime-images/stage1-metering/Dockerfile.security-candidate",
    "runtime-images/stage1-metering/b1_mock_gateway.py",
    "agentguard/evaluation/stage1_metering.py",
    "agentguard/evaluation/stage1_metering_gateway.py",
    "agentguard/evaluation/stage1_live_transport.py",
    "agentguard/evaluation/stage1_live_session.py",
    "agentguard/evaluation/stage1_live_pricing.py",
    "agentguard/evaluation/stage1_live_credential.py",
    "agentguard/evaluation/stage1_live_capabilities.py",
    "agentguard/evaluation/stage1_study_ledger.py",
    "agentguard/evaluation/stage1_pricing_v2.json",
)
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def _sha(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeImageError(f"evidence is not an object: {path.name}")
    return value


def _member_type(member: tarfile.TarInfo) -> str:
    for predicate, label in (
        (member.isfile, "file"), (member.isdir, "directory"),
        (member.issym, "symlink"), (member.islnk, "hardlink"),
        (member.ischr, "char"), (member.isblk, "block"),
        (member.isfifo, "fifo"),
    ):
        if predicate():
            return label
    return "other"


def rootfs_inventory(path: Path) -> list[dict]:
    entries = []
    with tarfile.open(path) as archive:
        for member in sorted(archive.getmembers(), key=lambda item: item.name):
            entry = {
                "name": member.name,
                "type": _member_type(member),
                "mode": member.mode,
                "uid": member.uid,
                "gid": member.gid,
                "linkname": member.linkname,
                "size": member.size if member.isfile() else 0,
            }
            if member.isfile():
                stream = archive.extractfile(member)
                if stream is None:
                    raise RuntimeImageError("rootfs file payload is missing")
                entry["sha256"] = hashlib.sha256(stream.read()).hexdigest()
            entries.append(entry)
    if not entries:
        raise RuntimeImageError("rootfs inventory is empty")
    return entries


def trivy_rows(document: dict) -> list[dict]:
    results = document.get("Results")
    if not isinstance(results, list) or not results:
        raise RuntimeImageError("Trivy Results are missing")
    rows = []
    for result in results:
        if not isinstance(result, dict):
            raise RuntimeImageError("Trivy result is malformed")
        findings = result.get("Vulnerabilities")
        if findings is None:
            findings = []
        if not isinstance(findings, list):
            raise RuntimeImageError("Trivy vulnerabilities are malformed")
        for finding in findings:
            if not isinstance(finding, dict):
                raise RuntimeImageError("Trivy finding is malformed")
            severity = finding.get("Severity")
            if severity not in {"HIGH", "CRITICAL"}:
                raise RuntimeImageError("scan contains unexpected severity")
            row = {
                "cve": finding.get("VulnerabilityID"),
                "severity": severity,
                "package": finding.get("PkgName"),
                "installed_version": finding.get("InstalledVersion"),
                "fixed_version": finding.get("FixedVersion") or "",
                "status": finding.get("Status") or "",
                "source_package": finding.get("SrcName") or "",
                "result_type": result.get("Type") or "",
                "target": result.get("Target") or "",
            }
            if any(not isinstance(value, str) for value in row.values()):
                raise RuntimeImageError("Trivy finding field is malformed")
            if not row["cve"] or not row["package"] or not row["installed_version"]:
                raise RuntimeImageError("Trivy finding identity is incomplete")
            rows.append(row)
    return sorted(rows, key=lambda row: json.dumps(row, sort_keys=True))


def summarize(root: Path, commit: str) -> dict:
    if not _COMMIT.fullmatch(commit):
        raise RuntimeImageError("source commit must be a full SHA")
    source_hashes = {name: _sha(ROOT / name) for name in SOURCE_FILES}
    builds = {}
    for build in ("a", "b"):
        identity = _json(root / f"{build}.identity.json")
        if identity.get("image_role") != "gateway" or identity.get("base_image") != GATEWAY_BASE_IMAGE:
            raise RuntimeImageError("candidate identity has wrong role or base")
        if identity.get("runtime_config", {}).get("architecture") != "amd64":
            raise RuntimeImageError("candidate architecture is not amd64")
        if identity["runtime_config"].get("user") != "65532:65532":
            raise RuntimeImageError("candidate is not the fixed non-root user")
        inventory = rootfs_inventory(root / f"{build}.rootfs.tar")
        if canonical_json_digest({"entries": inventory}) != identity["rootfs_digest"]:
            raise RuntimeImageError("rootfs inventory differs from canonical identity")
        (root / f"{build}.rootfs-inventory.json").write_text(
            json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8",
        )
        sbom = _json(root / f"{build}.sbom.json")
        packages = normalized_sbom_package_rows(sbom)
        (root / f"{build}.sbom-rows.json").write_text(
            json.dumps(packages, indent=2, sort_keys=True) + "\n", encoding="utf-8",
        )
        license_inventory = [
            {"name": row["name"], "version": row["version"],
             "type": row["type"], "purl": row["purl"], "licenses": row["licenses"]}
            for row in packages
        ]
        (root / f"{build}.license-inventory.json").write_text(
            json.dumps(license_inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8",
        )
        findings = trivy_rows(_json(root / f"{build}.trivy.json"))
        (root / f"{build}.findings.json").write_text(
            json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8",
        )
        builds[build] = {
            "identity": identity["identity"],
            "rootfs_digest": identity["rootfs_digest"],
            "runtime_config_digest": identity["runtime_config_digest"],
            "runtime_config": identity["runtime_config"],
            "rootfs_inventory_digest": canonical_json_digest(inventory),
            "sbom_rows_digest": canonical_json_digest(packages),
            "sbom_package_count": len(packages),
            "license_inventory_digest": canonical_json_digest(license_inventory),
            "findings_digest": canonical_json_digest(findings),
            "high_count": sum(row["severity"] == "HIGH" for row in findings),
            "critical_count": sum(row["severity"] == "CRITICAL" for row in findings),
            "fixable_high_critical_count": sum(bool(row["fixed_version"]) for row in findings),
            "archive_digest": _sha(root / f"{build}.image.tar"),
            "raw_sbom_digest": _sha(root / f"{build}.sbom.json"),
            "raw_trivy_digest": _sha(root / f"{build}.trivy.json"),
        }
    equal_fields = (
        "identity", "rootfs_digest", "runtime_config_digest", "runtime_config",
        "rootfs_inventory_digest", "sbom_rows_digest", "license_inventory_digest",
        "findings_digest",
    )
    reproducible = all(builds["a"][field] == builds["b"][field] for field in equal_fields)
    db = _json(root / "trivy-db-metadata.json")
    notices = {name: _sha(ROOT / name) for name in ("LICENSE", "NOTICE") if (ROOT / name).is_file()}
    summary = {
        "schema": "agentguard.stage1-metering-security-evidence",
        "schema_version": 1,
        "source_commit": commit,
        "platform": "linux/amd64",
        "base_image": GATEWAY_BASE_IMAGE,
        "base_inspect_digest": _sha(root / "base.inspect.json"),
        "source_hashes": source_hashes,
        "source_digest": canonical_json_digest(source_hashes),
        "candidate_capability": {
            "schema": "agentguard.stage1-metering-security-candidate-capability",
            "schema_version": 1,
            "mode": "local-tls-mock-only",
            "approved_live_subjects": [],
            "upstream_destination_in_live_source": "api.openai.com:443",
            "upstream_operations_in_live_source": [
                "POST /v1/responses/input_tokens", "POST /v1/responses",
            ],
            "runtime_user": "65532:65532",
            "platform": "linux/amd64",
            "source_digest": canonical_json_digest(source_hashes),
        },
        "pricing_policy_digest": pricing_policy_digest(),
        "ledger_schema": "agentguard.stage1-study-ledger/v1",
        "license_notice_digests": notices,
        "docker_version_digest": _sha(root / "docker-version.txt"),
        "buildx_version_digest": _sha(root / "buildx-version.txt"),
        "trivy_version_digest": _sha(root / "trivy-version.txt"),
        "trivy_db_metadata": db,
        "trivy_db_metadata_digest": _sha(root / "trivy-db-metadata.json"),
        "builds": builds,
        "reproducible": reproducible,
        "security_review_required": any(
            build["high_count"] or build["critical_count"] for build in builds.values()
        ),
    }
    summary["candidate_capability_digest"] = canonical_json_digest(summary["candidate_capability"])
    (root / "security-evidence.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--enforce", action="store_true")
    args = parser.parse_args()
    try:
        summary = summarize(args.root, args.source_commit)
    except (OSError, KeyError, ValueError, tarfile.TarError) as error:
        print(f"metering candidate evidence is invalid: {type(error).__name__}", file=sys.stderr)
        return 2
    if not summary["reproducible"]:
        print("metering candidate A/B evidence differs", file=sys.stderr)
        return 3
    if args.enforce and any(item["fixable_high_critical_count"] for item in summary["builds"].values()):
        print("metering candidate has fixable HIGH/CRITICAL findings", file=sys.stderr)
        return 5
    if args.enforce and summary["security_review_required"]:
        print("metering candidate has HIGH/CRITICAL findings requiring exact review", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
