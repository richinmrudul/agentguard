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
    VULNERABILITY_EXCEPTION_MANIFEST,
    RuntimeImageError,
    evaluate_trivy_high_critical_policy,
    load_vulnerability_exceptions,
    runtime_image_context_digest,
    validate_scanner_metadata,
)


SCHEMA = "agentguard.stage1-runtime-publication"
SCHEMA_VERSION = 1
SCAN_BINDINGS_SCHEMA = "agentguard.stage1-runtime-post-pull-scan-bindings"
SCAN_BINDINGS_SCHEMA_VERSION = 1
REJECTED_PUBLICATIONS_SCHEMA = "agentguard.stage1-runtime-rejected-publications"
REJECTED_PUBLICATIONS_SCHEMA_VERSION = 1
PLATFORM = "linux/amd64"
GATEWAY_PACKAGES = 38
AGENT_PACKAGES = 5
GATEWAY_HIGH_OCCURRENCES = 26
GATEWAY_EXCEPTION_COUNT = 10
EXCEPTION_EXPIRY = "2026-11-06"
GATEWAY_REPOSITORY = "ghcr.io/richinmrudul/agentguard/stage1-gateway"
AGENT_REPOSITORY = "ghcr.io/richinmrudul/agentguard/stage1-codex-agent"
REPOSITORIES = {
    "gateway": GATEWAY_REPOSITORY,
    "agent": AGENT_REPOSITORY,
}
ARCHIVES = {
    "gateway": "gateway-image.tar",
    "agent": "agent-image.tar",
}
PULLED_SCAN_FILENAMES = {
    "gateway": "gateway.pulled.trivy.json",
    "agent": "agent.pulled.trivy.json",
}
PULLED_SBOM_FILENAMES = {
    "gateway": "gateway.pulled.sbom.json",
    "agent": "agent.pulled.sbom.json",
}
REJECTED_PUBLICATIONS = ROOT / "runtime-images/rejected-publications.json"
MAX_ARCHIVE_BYTES = 3 * 1024 * 1024 * 1024


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

    bindings = subparsers.add_parser("write-scan-bindings")
    bindings.add_argument("--root", type=Path, required=True)
    bindings.add_argument("--post-root", type=Path, required=True)
    bindings.add_argument("--gateway-digest", required=True)
    bindings.add_argument("--agent-digest", required=True)
    bindings.add_argument("--output", type=Path, required=True)

    rejected = subparsers.add_parser("check-rejected")
    rejected.add_argument("--gateway-digest", required=True)
    rejected.add_argument("--agent-digest", required=True)

    archives = subparsers.add_parser("verify-archives")
    archives.add_argument("--root", type=Path, required=True)
    archives.add_argument("--source-commit", required=True)
    archives.add_argument("--gateway-image", required=True)
    archives.add_argument("--agent-image", required=True)

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
        elif args.command == "write-scan-bindings":
            bindings = build_post_pull_scan_bindings(
                root=args.root,
                post_root=args.post_root,
                gateway_digest=args.gateway_digest,
                agent_digest=args.agent_digest,
            )
            args.output.write_text(
                json.dumps(bindings, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        elif args.command == "check-rejected":
            ensure_not_rejected_publications(
                {
                    "gateway": (GATEWAY_REPOSITORY, args.gateway_digest),
                    "agent": (AGENT_REPOSITORY, args.agent_digest),
                }
            )
        elif args.command == "verify-archives":
            verify_archive_boundary(
                root=args.root,
                source_commit=args.source_commit,
                gateway_image=args.gateway_image,
                agent_image=args.agent_image,
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
        "gateway": _sbom_summary(
            root / "gateway.sbom.json",
            GATEWAY_PACKAGES,
            rows_output=root / "gateway.sbom.rows.json",
        ),
        "agent": _sbom_summary(
            root / "agent.sbom.json",
            AGENT_PACKAGES,
            rows_output=root / "agent.sbom.rows.json",
        ),
    }
    policy = evaluate_trivy_high_critical_policy(
        [root / "gateway.trivy.json", root / "agent.trivy.json"],
        exception_manifest=ROOT / VULNERABILITY_EXCEPTION_MANIFEST,
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
        ROOT / VULNERABILITY_EXCEPTION_MANIFEST,
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
            "exception_manifest_digest": "sha256:" + _sha256_file(ROOT / VULNERABILITY_EXCEPTION_MANIFEST),
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
    ensure_not_rejected_publications(
        {
            "gateway": (GATEWAY_REPOSITORY, gateway_digest),
            "agent": (AGENT_REPOSITORY, agent_digest),
        }
    )
    bindings = validate_post_pull_scan_bindings(
        root=root,
        post_root=post_root,
        gateway_digest=gateway_digest,
        agent_digest=agent_digest,
    )
    identities = {
        "gateway": (post_root / "gateway.identity.json", GATEWAY_REVIEWED_IMAGE_DIGEST),
        "agent": (post_root / "agent.identity.json", AGENT_REVIEWED_IMAGE_DIGEST),
    }
    for role, (path, expected) in identities.items():
        actual = _identity(path, role)["identity"]
        if actual != expected:
            raise RuntimeImageError(f"{role} pulled digest canonical identity mismatch")
    for role, expected in (("gateway", GATEWAY_PACKAGES), ("agent", AGENT_PACKAGES)):
        prepared = _image_manifest(manifest, role)
        actual = _sbom_summary(
            post_root / f"{role}.pulled.sbom.json",
            expected,
            rows_output=post_root / f"{role}.pulled.sbom.rows.json",
        )
        if actual["rows_digest"] != prepared.get("sbom_rows_digest"):
            raise RuntimeImageError(f"{role} post-publication SBOM package rows mismatch")
        if actual["package_count"] != prepared.get("sbom_package_count"):
            raise RuntimeImageError(f"{role} post-publication SBOM package count mismatch")
    scan_paths = [post_root / PULLED_SCAN_FILENAMES["gateway"], post_root / PULLED_SCAN_FILENAMES["agent"]]
    policy = evaluate_trivy_high_critical_policy(
        scan_paths,
        exception_manifest=ROOT / VULNERABILITY_EXCEPTION_MANIFEST,
        gateway_image_digest=GATEWAY_REVIEWED_IMAGE_DIGEST,
        agent_image_digest=AGENT_REVIEWED_IMAGE_DIGEST,
        image_roles_by_path={
            str(post_root / item["scan_path"]): item["role"]
            for item in bindings["scans"]
        },
        as_of=date.today(),
    )
    if policy.get("status") != "hosted_trivy_high_critical_policy_passed":
        raise RuntimeImageError("post-publication vulnerability policy failed")
    if policy.get("severity_counts") != {"CRITICAL": 0, "HIGH": GATEWAY_HIGH_OCCURRENCES}:
        raise RuntimeImageError("post-publication vulnerability count mismatch")
    if policy.get("exception_count") != GATEWAY_EXCEPTION_COUNT:
        raise RuntimeImageError("post-publication exception count mismatch")


def build_post_pull_scan_bindings(
    *,
    root: Path,
    post_root: Path,
    gateway_digest: str,
    agent_digest: str,
) -> dict[str, Any]:
    manifest = _json(root / "publication-manifest.json")
    if manifest.get("schema") != SCHEMA:
        raise RuntimeImageError("invalid publication manifest schema")
    if manifest.get("platform") != PLATFORM:
        raise RuntimeImageError("publication manifest platform mismatch")
    digests = {"gateway": gateway_digest, "agent": agent_digest}
    for role, digest in digests.items():
        _require_digest(digest, f"{role} published digest")
    scans = []
    for role in ("gateway", "agent"):
        image = _image_manifest(manifest, role)
        if image.get("role") != role:
            raise RuntimeImageError(f"{role} publication manifest role mismatch")
        repository = image.get("repository")
        if repository != REPOSITORIES[role]:
            raise RuntimeImageError(f"{role} publication repository mismatch")
        archive_name = image.get("archive_name")
        if archive_name != ARCHIVES[role]:
            raise RuntimeImageError(f"{role} prepared archive role mismatch")
        canonical_identity = image.get("canonical_identity")
        expected_identity = (
            GATEWAY_REVIEWED_IMAGE_DIGEST if role == "gateway" else AGENT_REVIEWED_IMAGE_DIGEST
        )
        if canonical_identity != expected_identity:
            raise RuntimeImageError(f"{role} canonical identity mismatch")
        digest = digests[role]
        scans.append(
            {
                "role": role,
                "repository": repository,
                "digest": digest,
                "pulled_reference": f"{repository}@{digest}",
                "prepared_archive_role": role,
                "prepared_archive_name": archive_name,
                "canonical_identity": canonical_identity,
                "scan_path": PULLED_SCAN_FILENAMES[role],
                "sbom_path": PULLED_SBOM_FILENAMES[role],
                "pulled_archive_name": f"{role}-pulled-image.tar",
            }
        )
    result = {
        "schema": SCAN_BINDINGS_SCHEMA,
        "schema_version": SCAN_BINDINGS_SCHEMA_VERSION,
        "source": manifest.get("source"),
        "platform": PLATFORM,
        "scans": scans,
    }
    validate_post_pull_scan_bindings(
        root=root,
        post_root=post_root,
        gateway_digest=gateway_digest,
        agent_digest=agent_digest,
        bindings=result,
    )
    return result


def validate_post_pull_scan_bindings(
    *,
    root: Path,
    post_root: Path,
    gateway_digest: str,
    agent_digest: str,
    bindings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest = _json(root / "publication-manifest.json")
    data = bindings if bindings is not None else _json(post_root / "scan-bindings.json")
    if data.get("schema") != SCAN_BINDINGS_SCHEMA:
        raise RuntimeImageError("invalid post-pull scan binding schema")
    if data.get("schema_version") != SCAN_BINDINGS_SCHEMA_VERSION:
        raise RuntimeImageError("unsupported post-pull scan binding version")
    if data.get("platform") != PLATFORM:
        raise RuntimeImageError("post-pull scan binding platform mismatch")
    if data.get("source") != manifest.get("source"):
        raise RuntimeImageError("post-pull scan binding source mismatch")
    scans = data.get("scans")
    if not isinstance(scans, list):
        raise RuntimeImageError("post-pull scan bindings must be a list")
    expected_digests = {"gateway": gateway_digest, "agent": agent_digest}
    expected_roles = {"gateway", "agent"}
    seen: set[str] = set()
    for index, item in enumerate(scans):
        label = f"post-pull scan binding {index}"
        if not isinstance(item, dict):
            raise RuntimeImageError(f"{label} must be an object")
        role = item.get("role")
        if role not in expected_roles:
            raise RuntimeImageError(f"{label} unknown role")
        if role in seen:
            raise RuntimeImageError(f"duplicate post-pull scan role: {role}")
        seen.add(role)
        image = _image_manifest(manifest, role)
        repository = item.get("repository")
        if repository != REPOSITORIES[role] or repository != image.get("repository"):
            raise RuntimeImageError(f"{role} post-pull repository mismatch")
        digest = item.get("digest")
        if digest != expected_digests[role]:
            raise RuntimeImageError(f"{role} post-pull digest mismatch")
        _require_digest(digest, f"{role} post-pull digest")
        expected_reference = f"{repository}@{digest}"
        if item.get("pulled_reference") != expected_reference:
            raise RuntimeImageError(f"{role} post-pull reference must be immutable")
        if item.get("prepared_archive_role") != role:
            raise RuntimeImageError(f"{role} prepared archive role mismatch")
        if item.get("prepared_archive_name") != ARCHIVES[role]:
            raise RuntimeImageError(f"{role} prepared archive name mismatch")
        if item.get("canonical_identity") != image.get("canonical_identity"):
            raise RuntimeImageError(f"{role} canonical identity binding mismatch")
        if item.get("scan_path") != PULLED_SCAN_FILENAMES[role]:
            raise RuntimeImageError(f"{role} scan path mismatch")
        if item.get("sbom_path") != PULLED_SBOM_FILENAMES[role]:
            raise RuntimeImageError(f"{role} SBOM path mismatch")
        if item.get("pulled_archive_name") != f"{role}-pulled-image.tar":
            raise RuntimeImageError(f"{role} pulled archive name mismatch")
        for path_key in ("scan_path", "sbom_path", "pulled_archive_name"):
            _artifact_basename(str(item[path_key]), f"{role} {path_key}")
        if not (post_root / item["scan_path"]).exists():
            raise RuntimeImageError(f"{role} post-pull scan is missing")
        _validate_scan_artifact_reference(
            post_root / item["scan_path"],
            role=role,
            repository=repository,
            digest=digest,
        )
    if seen != expected_roles:
        raise RuntimeImageError("missing post-pull scan role")
    return data


def _validate_scan_artifact_reference(
    path: Path,
    *,
    role: str,
    repository: str,
    digest: str,
) -> None:
    data = _json(path)
    candidates: list[str] = []
    artifact = data.get("ArtifactName")
    if isinstance(artifact, str):
        candidates.append(artifact)
    for result in data.get("Results") or []:
        if isinstance(result, dict) and isinstance(result.get("Target"), str):
            candidates.append(result["Target"])
    for candidate in candidates:
        if "@sha256:" not in candidate:
            continue
        if candidate != f"{repository}@{digest}":
            raise RuntimeImageError(f"{role} scan artifact reference mismatch")
    if any(
        candidate.startswith("ghcr.io/") and "@sha256:" not in candidate
        for candidate in candidates
    ):
        raise RuntimeImageError(f"{role} scan artifact reference must be immutable")


def verify_archive_boundary(
    *,
    root: Path,
    source_commit: str,
    gateway_image: str,
    agent_image: str,
) -> None:
    root = root.resolve()
    _require_commit(source_commit)
    manifest = _json(root / "publication-manifest.json")
    if manifest.get("schema") != SCHEMA:
        raise RuntimeImageError("invalid publication manifest schema")
    if manifest.get("platform") != PLATFORM:
        raise RuntimeImageError("publication manifest platform mismatch")
    if manifest.get("source", {}).get("commit") != source_commit:
        raise RuntimeImageError("publication manifest source commit mismatch")
    expected_tags = {"gateway": gateway_image, "agent": agent_image}
    checksums = _read_archive_checksums(root / "image-archives.SHA256SUMS")
    if set(checksums) != set(ARCHIVES.values()):
        raise RuntimeImageError("archive checksum file must list exactly gateway and agent archives")
    for role, filename in ARCHIVES.items():
        image = _image_manifest(manifest, role)
        if image.get("role") != role:
            raise RuntimeImageError(f"{role} archive role mismatch")
        if image.get("tag") != expected_tags[role]:
            raise RuntimeImageError(f"{role} image coordinate mismatch")
        if image.get("archive_name") != filename:
            raise RuntimeImageError(f"{role} archive filename mismatch")
        path = _archive_path(root, filename)
        actual_digest = "sha256:" + _sha256_file(path)
        manifest_digest = image.get("archive_digest")
        checksum_digest = "sha256:" + checksums[filename]
        if manifest_digest != checksum_digest or actual_digest != manifest_digest:
            raise RuntimeImageError(f"{role} archive digest mismatch")


def ensure_not_rejected_publications(candidates: dict[str, tuple[str, str]]) -> None:
    rejected = load_rejected_publications(REJECTED_PUBLICATIONS)
    rejected_keys = {
        (item["role"], item["repository"], item["digest"])
        for item in rejected
    }
    for role, (repository, digest) in candidates.items():
        if (role, repository, digest) in rejected_keys:
            raise RuntimeImageError(f"{role} published digest is recorded as rejected")


def load_rejected_publications(path: Path = REJECTED_PUBLICATIONS) -> list[dict[str, Any]]:
    data = _json(path)
    if data.get("schema") != REJECTED_PUBLICATIONS_SCHEMA:
        raise RuntimeImageError("invalid rejected-publications schema")
    if data.get("schema_version") != REJECTED_PUBLICATIONS_SCHEMA_VERSION:
        raise RuntimeImageError("unsupported rejected-publications version")
    records = data.get("rejected_publications")
    if not isinstance(records, list):
        raise RuntimeImageError("rejected-publications records must be a list")
    seen: set[tuple[str, str, str]] = set()
    result: list[dict[str, Any]] = []
    for index, item in enumerate(records):
        label = f"rejected_publications[{index}]"
        if not isinstance(item, dict):
            raise RuntimeImageError(f"{label} must be an object")
        role = item.get("role")
        if role not in {"gateway", "agent"}:
            raise RuntimeImageError(f"{label} role must be gateway or agent")
        repository = item.get("repository")
        if repository != REPOSITORIES[role]:
            raise RuntimeImageError(f"{label} repository mismatch")
        digest = item.get("digest")
        _require_digest(digest, f"{label} digest")
        key = (role, repository, digest)
        if key in seen:
            raise RuntimeImageError(f"duplicate rejected publication: {role} {digest}")
        seen.add(key)
        if item.get("status") != "rejected":
            raise RuntimeImageError(f"{label} status must be rejected")
        if item.get("eligible_for_study") is not False:
            raise RuntimeImageError(f"{label} must not be study eligible")
        _require_commit(_required_record_string(item, "source_commit", label))
        _required_record_string(item, "run_id", label)
        _required_record_string(item, "run_attempt", label)
        _required_record_string(item, "failure_stage", label)
        _required_record_string(item, "rejection_reason", label)
        _require_date(
            _required_record_string(item, "rejected_at", label),
            f"{label} rejected_at",
        )
        evidence = item.get("evidence")
        if not isinstance(evidence, dict):
            raise RuntimeImageError(f"{label} evidence must be an object")
        _required_record_string(evidence, "workflow_run_url", f"{label} evidence")
        _required_record_string(evidence, "issue_comment_url", f"{label} evidence")
        result.append(item)
    return result


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
        "archive_name": archive.name,
        "canonical_identity": identity["identity"],
        "rootfs_digest": identity["rootfs_digest"],
        "runtime_config_digest": identity["runtime_config_digest"],
        "base_image": base_image,
        "dockerfile_digest": "sha256:" + _sha256_file(dockerfile),
        "build_context_digest": runtime_image_context_digest(context),
        "sbom_digest": sbom["digest"],
        "sbom_package_count": sbom["package_count"],
        "sbom_rows_digest": sbom["rows_digest"],
        "sbom_rows_schema": sbom["rows_schema"],
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


def _sbom_summary(
    path: Path,
    expected_count: int,
    *,
    rows_output: Path | None = None,
) -> dict[str, Any]:
    data = _json(path)
    rows = normalized_sbom_package_rows(data)
    if len(rows) != expected_count:
        raise RuntimeImageError(f"SBOM package count mismatch for {path}")
    if rows_output is not None:
        rows_output.write_text(
            json.dumps(rows, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return {
        "digest": "sha256:" + _sha256_file(path),
        "package_count": len(rows),
        "rows_digest": "sha256:" + _sha256_json(rows),
        "rows_schema": "agentguard.stage1-runtime-sbom-package-rows.v1",
    }


def normalized_sbom_package_rows(data: object) -> list[dict[str, Any]]:
    document = data if isinstance(data, dict) else None
    if document is None:
        raise RuntimeImageError("SBOM must be a JSON object")
    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list):
        raise RuntimeImageError("missing SBOM artifacts")
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(artifacts):
        if not isinstance(item, dict):
            raise RuntimeImageError(f"SBOM package row {index} must be an object")
        row = {
            "type": _required_package_string(item, "type", index),
            "name": _required_package_string(item, "name", index),
            "version": _required_package_string(item, "version", index),
            "purl": _optional_package_string(item.get("purl"), "purl", index),
            "licenses": _normalized_licenses(item.get("licenses"), index),
        }
        rows.append(row)
    rows.sort(
        key=lambda row: (
            row["type"],
            row["name"],
            row["version"],
            row["purl"],
            tuple(row["licenses"]),
        )
    )
    return rows


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


def _image_manifest(manifest: dict[str, Any], role: str) -> dict[str, Any]:
    images = manifest.get("images")
    if not isinstance(images, dict):
        raise RuntimeImageError("publication manifest images must be an object")
    image = images.get(role)
    if not isinstance(image, dict):
        raise RuntimeImageError(f"publication manifest missing {role} image")
    return image


def _archive_path(root: Path, filename: str) -> Path:
    _artifact_basename(filename, "archive filename")
    path = root / filename
    try:
        relative = path.resolve(strict=False).relative_to(root)
    except ValueError as error:
        raise RuntimeImageError("archive path escapes artifact directory") from error
    if relative.as_posix() != filename:
        raise RuntimeImageError("archive path must not traverse directories")
    if not path.exists() or path.is_symlink() or not path.is_file():
        raise RuntimeImageError(f"archive must be a regular file: {filename}")
    size = path.stat().st_size
    if size <= 0 or size > MAX_ARCHIVE_BYTES:
        raise RuntimeImageError(f"archive size is out of bounds: {filename}")
    return path


def _artifact_basename(filename: str, label: str) -> None:
    if filename.startswith("/") or "/" in filename or filename in {"", ".", ".."}:
        raise RuntimeImageError(f"{label} must be a local basename")
    if "\\" in filename or "\x00" in filename:
        raise RuntimeImageError(f"{label} must be a local basename")


def _read_archive_checksums(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw:
            continue
        parts = raw.split()
        if len(parts) != 2:
            raise RuntimeImageError(f"malformed archive checksum line {line_number}")
        digest, filename = parts
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise RuntimeImageError(f"malformed archive checksum digest on line {line_number}")
        if filename in checksums:
            raise RuntimeImageError(f"duplicate archive checksum entry: {filename}")
        if filename.startswith("/") or "/" in filename or filename in {"", ".", ".."}:
            raise RuntimeImageError(f"invalid archive checksum filename: {filename}")
        checksums[filename] = digest
    if not checksums:
        raise RuntimeImageError("archive checksum file is empty")
    return checksums


def _required_package_string(item: dict[str, Any], key: str, index: int) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeImageError(f"SBOM package row {index} missing {key}")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise RuntimeImageError(f"SBOM package row {index} has invalid {key}")
    return value.strip()


def _optional_package_string(value: object, key: str, index: int) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise RuntimeImageError(f"SBOM package row {index} has invalid {key}")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise RuntimeImageError(f"SBOM package row {index} has invalid {key}")
    return value.strip()


def _normalized_licenses(value: object, index: int) -> list[str]:
    if value in (None, ""):
        return []
    if not isinstance(value, list):
        raise RuntimeImageError(f"SBOM package row {index} has invalid licenses")
    normalized: list[str] = []
    for license_item in value:
        if isinstance(license_item, str):
            text = license_item
        elif isinstance(license_item, dict):
            candidate = (
                license_item.get("value")
                or license_item.get("spdxExpression")
                or license_item.get("expression")
            )
            if not isinstance(candidate, str):
                raise RuntimeImageError(f"SBOM package row {index} has invalid license")
            text = candidate
        else:
            raise RuntimeImageError(f"SBOM package row {index} has invalid license")
        text = text.strip()
        if text and not any(ord(character) < 32 or ord(character) == 127 for character in text):
            normalized.append(text)
    return sorted(set(normalized))


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


def _required_record_string(item: dict[str, Any], key: str, label: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeImageError(f"{label} {key} is required")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise RuntimeImageError(f"{label} {key} contains invalid characters")
    return value.strip()


def _require_date(value: str, label: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise RuntimeImageError(f"{label} must be YYYY-MM-DD") from error


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
