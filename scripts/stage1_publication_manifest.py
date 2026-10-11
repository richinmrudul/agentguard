#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentguard.evaluation.runtime_images import (  # noqa: E402
    AGENT_BASE_IMAGE,
    AGENT_REVIEWED_IMAGE_DIGEST,
    CODEX_INTEGRITY,
    CODEX_LINUX_X64_INTEGRITY,
    CODEX_LINUX_X64_VERSION,
    CODEX_PACKAGE,
    CODEX_VERSION,
    GATEWAY_BASE_IMAGE,
    GATEWAY_REVIEWED_IMAGE_DIGEST,
    RuntimeImageError,
    evaluate_trivy_high_critical_policy,
    load_vulnerability_exceptions,
    runtime_image_context_digest,
    validate_scanner_metadata,
)


SCHEMA = "agentguard.stage1-runtime-publication"
SCHEMA_VERSION = 1
PLATFORM = "linux/amd64"
GATEWAY_PACKAGES = 38
AGENT_PACKAGES = 5
GATEWAY_HIGH_OCCURRENCES = 31
GATEWAY_EXCEPTION_COUNT = 15
EXCEPTION_EXPIRY = "2026-11-06"
GATEWAY_REPOSITORY = "ghcr.io/richinmrudul/agentguard/stage1-gateway"
AGENT_REPOSITORY = "ghcr.io/richinmrudul/agentguard/stage1-codex-agent"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--root", type=Path, required=True)
    prepare.add_argument("--source-commit", required=True)
    prepare.add_argument("--workflow", required=True)
    prepare.add_argument("--run-id", required=True)
    prepare.add_argument("--run-attempt", required=True)
    prepare.add_argument("--gateway-image", required=True)
    prepare.add_argument("--agent-image", required=True)
    prepare.add_argument("--output", type=Path, required=True)

    post = subparsers.add_parser("post-publish")
    post.add_argument("--root", type=Path, required=True)
    post.add_argument("--post-root", type=Path, required=True)
    post.add_argument("--gateway-digest", required=True)
    post.add_argument("--agent-digest", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            manifest = build_prepare_manifest(
                root=args.root,
                source_commit=args.source_commit,
                workflow=args.workflow,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                gateway_image=args.gateway_image,
                agent_image=args.agent_image,
            )
            args.output.write_text(
                json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        elif args.command == "post-publish":
            validate_post_publish(
                root=args.root,
                post_root=args.post_root,
                gateway_digest=args.gateway_digest,
                agent_digest=args.agent_digest,
            )
        else:  # pragma: no cover - argparse prevents this.
            raise RuntimeImageError("unsupported command")
    except (OSError, json.JSONDecodeError, RuntimeImageError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


def build_prepare_manifest(
    *,
    root: Path,
    source_commit: str,
    workflow: str,
    run_id: str,
    run_attempt: str,
    gateway_image: str,
    agent_image: str,
) -> dict[str, Any]:
    root = root.resolve()
    _require_commit(source_commit)
    _require_tag(gateway_image, GATEWAY_REPOSITORY, source_commit, "gateway")
    _require_tag(agent_image, AGENT_REPOSITORY, source_commit, "agent")

    gateway_identity = _identity(root / "gateway.identity.json", "gateway")
    agent_identity = _identity(root / "agent.identity.json", "agent")
    if gateway_identity["identity"] != GATEWAY_REVIEWED_IMAGE_DIGEST:
        raise RuntimeImageError("gateway canonical identity does not match review")
    if agent_identity["identity"] != AGENT_REVIEWED_IMAGE_DIGEST:
        raise RuntimeImageError("agent canonical identity does not match review")

    sbom = {
        "gateway": _sbom_summary(root / "gateway.sbom.json", GATEWAY_PACKAGES),
        "agent": _sbom_summary(root / "agent.sbom.json", AGENT_PACKAGES),
    }
    policy = evaluate_trivy_high_critical_policy(
        [root / "gateway.trivy.json", root / "agent.trivy.json"],
        exception_manifest=ROOT / "runtime-images/vulnerability-exceptions.json",
        gateway_image_digest=GATEWAY_REVIEWED_IMAGE_DIGEST,
        agent_image_digest=AGENT_REVIEWED_IMAGE_DIGEST,
        as_of=date.today(),
    )
    if policy.get("status") != "hosted_trivy_high_critical_policy_passed":
        raise RuntimeImageError("vulnerability exception policy failed")
    if policy.get("severity_counts") != {"CRITICAL": 0, "HIGH": GATEWAY_HIGH_OCCURRENCES}:
        raise RuntimeImageError("reviewed vulnerability occurrence count mismatch")
    if policy.get("fixability_counts", {}).get("fixed") != {"CRITICAL": 0, "HIGH": 0}:
        raise RuntimeImageError("fixable high/critical vulnerability count mismatch")
    if policy.get("exception_count") != GATEWAY_EXCEPTION_COUNT:
        raise RuntimeImageError("reviewed exception count mismatch")

    scanner_metadata = _scanner_metadata(root)
    policy["scanner_metadata"] = validate_scanner_metadata(scanner_metadata)
    exceptions = load_vulnerability_exceptions(
        ROOT / "runtime-images/vulnerability-exceptions.json",
        gateway_image_digest=GATEWAY_REVIEWED_IMAGE_DIGEST,
        as_of=date.today(),
    )
    expiries = sorted({item["expiry_date"] for item in exceptions})
    if expiries != [EXCEPTION_EXPIRY]:
        raise RuntimeImageError("reviewed exception expiry mismatch")

    mock_result = (root / "mock-provider-integration.txt").read_text(encoding="utf-8")
    if "mock-provider-gateway-runtime-ok" not in mock_result or "codex-cli 0.159.2" not in mock_result:
        raise RuntimeImageError("mock integration evidence is incomplete")

    manifest: dict[str, Any] = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "source": {
            "repository": "https://github.com/richinmrudul/agentguard",
            "commit": source_commit,
        },
        "workflow": {
            "name": workflow,
            "file": ".github/workflows/stage1-runtime-images-publish.yml",
            "run_id": run_id,
            "run_attempt": run_attempt,
        },
        "activation": {
            "repository_variable": "STAGE1_RUNTIME_PUBLICATION_ENABLED",
            "required_value": "true",
            "environment": "stage1-runtime-images",
        },
        "platform": PLATFORM,
        "images": {
            "gateway": _image_record(
                role="gateway",
                tag=gateway_image,
                repository=GATEWAY_REPOSITORY,
                archive=root / "gateway-image.tar",
                identity=gateway_identity,
                base_image=GATEWAY_BASE_IMAGE,
                context=ROOT / "runtime-images/gateway",
                sbom=sbom["gateway"],
                scan=root / "gateway.trivy.json",
            ),
            "agent": _image_record(
                role="agent",
                tag=agent_image,
                repository=AGENT_REPOSITORY,
                archive=root / "agent-image.tar",
                identity=agent_identity,
                base_image=AGENT_BASE_IMAGE,
                context=ROOT / "runtime-images/codex-agent",
                sbom=sbom["agent"],
                scan=root / "agent.trivy.json",
            ),
        },
        "codex": {
            "package": CODEX_PACKAGE,
            "version": CODEX_VERSION,
            "integrity": CODEX_INTEGRITY,
            "linux_x64_version": CODEX_LINUX_X64_VERSION,
            "linux_x64_integrity": CODEX_LINUX_X64_INTEGRITY,
        },
        "scanner": scanner_metadata,
        "vulnerability_policy": {
            "status": policy["status"],
            "severity_counts": policy["severity_counts"],
            "fixability_counts": policy["fixability_counts"],
            "exception_count": policy["exception_count"],
            "accepted_exception_count": policy["accepted_exception_count"],
            "exception_manifest_digest": "sha256:" + _sha256_file(ROOT / "runtime-images/vulnerability-exceptions.json"),
            "exception_expiry": EXCEPTION_EXPIRY,
        },
        "mock_integration": {
            "status": "passed",
            "evidence_digest": "sha256:" + _sha256_file(root / "mock-provider-integration.txt"),
        },
        "publication_policy": {
            "publish_from_validated_archives_only": True,
            "mutable_tags_forbidden": True,
            "latest_tag_forbidden": True,
            "post_publish_digest_pull_required": True,
        },
    }
    manifest["manifest_digest"] = "sha256:" + _sha256_json(manifest)
    return manifest


def validate_post_publish(
    *,
    root: Path,
    post_root: Path,
    gateway_digest: str,
    agent_digest: str,
) -> None:
    manifest = _json(root / "publication-manifest.json")
    if manifest.get("schema") != SCHEMA:
        raise RuntimeImageError("invalid publication manifest schema")
    if manifest.get("platform") != PLATFORM:
        raise RuntimeImageError("published platform mismatch")
    _require_digest(gateway_digest, "gateway published digest")
    _require_digest(agent_digest, "agent published digest")
    identities = {
        "gateway": (post_root / "gateway.identity.json", GATEWAY_REVIEWED_IMAGE_DIGEST),
        "agent": (post_root / "agent.identity.json", AGENT_REVIEWED_IMAGE_DIGEST),
    }
    for role, (path, expected) in identities.items():
        actual = _identity(path, role)["identity"]
        if actual != expected:
            raise RuntimeImageError(f"{role} pulled digest canonical identity mismatch")
    for role, expected in (("gateway", GATEWAY_PACKAGES), ("agent", AGENT_PACKAGES)):
        _sbom_summary(post_root / f"{role}.pulled.sbom.json", expected)
    policy = evaluate_trivy_high_critical_policy(
        [post_root / "gateway.pulled.trivy.json", post_root / "agent.pulled.trivy.json"],
        exception_manifest=ROOT / "runtime-images/vulnerability-exceptions.json",
        gateway_image_digest=GATEWAY_REVIEWED_IMAGE_DIGEST,
        agent_image_digest=AGENT_REVIEWED_IMAGE_DIGEST,
        as_of=date.today(),
    )
    if policy.get("status") != "hosted_trivy_high_critical_policy_passed":
        raise RuntimeImageError("post-publication vulnerability policy failed")
    if policy.get("severity_counts") != {"CRITICAL": 0, "HIGH": GATEWAY_HIGH_OCCURRENCES}:
        raise RuntimeImageError("post-publication vulnerability count mismatch")
    if policy.get("exception_count") != GATEWAY_EXCEPTION_COUNT:
        raise RuntimeImageError("post-publication exception count mismatch")


def _image_record(
    *,
    role: str,
    tag: str,
    repository: str,
    archive: Path,
    identity: dict[str, Any],
    base_image: str,
    context: Path,
    sbom: dict[str, Any],
    scan: Path,
) -> dict[str, Any]:
    dockerfile = context / "Dockerfile"
    return {
        "role": role,
        "repository": repository,
        "tag": tag,
        "archive_digest": "sha256:" + _sha256_file(archive),
        "canonical_identity": identity["identity"],
        "rootfs_digest": identity["rootfs_digest"],
        "runtime_config_digest": identity["runtime_config_digest"],
        "base_image": base_image,
        "dockerfile_digest": "sha256:" + _sha256_file(dockerfile),
        "build_context_digest": runtime_image_context_digest(context),
        "sbom_digest": sbom["digest"],
        "sbom_package_count": sbom["package_count"],
        "raw_scan_digest": "sha256:" + _sha256_file(scan),
    }


def _scanner_metadata(root: Path) -> dict[str, Any]:
    version_text = (root / "trivy-version.txt").read_text(encoding="utf-8")
    db_metadata_path = root / "trivy-db-metadata.json"
    db_metadata_text = db_metadata_path.read_text(encoding="utf-8")
    db_metadata = json.loads(db_metadata_text)
    trivy_version = ""
    for line in version_text.splitlines():
        if line.startswith("Version:"):
            trivy_version = line.split(":", 1)[1].strip()
            break
    return {
        "schema": "agentguard.stage1-runtime-scanner-metadata",
        "schema_version": 1,
        "trivy": {
            "version": trivy_version,
            "version_output_sha256": "sha256:" + hashlib.sha256(version_text.encode("utf-8")).hexdigest(),
        },
        "vulnerability_database": {
            "schema_version": db_metadata.get("Version") or db_metadata.get("SchemaVersion"),
            "updated_at": db_metadata.get("UpdatedAt", ""),
            "downloaded_at": db_metadata.get("DownloadedAt", ""),
            "next_update": db_metadata.get("NextUpdate", ""),
            "metadata_digest": "sha256:" + hashlib.sha256(db_metadata_text.encode("utf-8")).hexdigest(),
        },
    }


def _sbom_summary(path: Path, expected_count: int) -> dict[str, Any]:
    data = _json(path)
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list):
        raise RuntimeImageError(f"missing SBOM artifacts: {path}")
    if len(artifacts) != expected_count:
        raise RuntimeImageError(f"SBOM package count mismatch for {path}")
    rows = sorted(
        (
            str(item.get("type", "")),
            str(item.get("name", "")),
            str(item.get("version", "")),
            str(item.get("purl", "")),
        )
        for item in artifacts
    )
    return {
        "digest": "sha256:" + _sha256_file(path),
        "package_count": len(rows),
        "rows_digest": "sha256:" + _sha256_json(rows),
    }


def _identity(path: Path, role: str) -> dict[str, Any]:
    data = _json(path)
    if data.get("image_role") != role:
        raise RuntimeImageError(f"{role} identity role mismatch")
    for key in ("identity", "rootfs_digest", "runtime_config_digest", "runtime_config"):
        if key not in data:
            raise RuntimeImageError(f"{role} identity missing {key}")
    _require_digest(data["identity"], f"{role} canonical identity")
    _require_digest(data["rootfs_digest"], f"{role} rootfs digest")
    _require_digest(data["runtime_config_digest"], f"{role} runtime config digest")
    return data


def _json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeImageError(f"expected JSON object: {path}")
    return data


def _require_commit(value: str) -> None:
    if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
        raise RuntimeImageError("source commit must be a full lowercase SHA")


def _require_digest(value: object, label: str) -> None:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
        raise RuntimeImageError(f"{label} must be a sha256 digest")
    if any(character not in "0123456789abcdef" for character in value.removeprefix("sha256:")):
        raise RuntimeImageError(f"{label} must be a sha256 digest")


def _require_tag(value: str, repository: str, commit: str, label: str) -> None:
    if value != f"{repository}:{commit}":
        raise RuntimeImageError(f"{label} image must use the full source commit tag")
    if value.endswith(":latest"):
        raise RuntimeImageError("latest tags are forbidden")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_json(data: object) -> str:
    payload = json.dumps(data, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
