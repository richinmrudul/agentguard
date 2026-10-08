from __future__ import annotations

import hashlib
import json
import posixpath
import re
import tarfile
from datetime import date
from pathlib import Path
from typing import Any


RUNTIME_IMAGE_MANIFEST_SCHEMA = "agentguard.stage1-runtime-image-freeze"
RUNTIME_IMAGE_MANIFEST_SCHEMA_VERSION = 1
PLATFORM = "linux/amd64"
GATEWAY_BASE_IMAGE = (
    "gcr.io/distroless/python3-debian13:nonroot@"
    "sha256:339ecee37afe554f5237b9993250bc390ac9f1483a08c9b5e77ac4c016d6d39a"
)
GATEWAY_BASE_INDEX_DIGEST = (
    "sha256:774595d652a294b54c9bd575b2d9fdd1a4b47547dc17b8bfa4c0e953c64855b3"
)
AGENT_BASE_IMAGE = (
    "gcr.io/distroless/static-debian12:nonroot@"
    "sha256:52dcfbabb7457ea47c82f6e13af8c8a4a1d9f7b0145142b3ecab20f2b888411d"
)
AGENT_BASE_INDEX_DIGEST = (
    "sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab"
)
AGENT_BUILDER_BASE_IMAGE = (
    "node:22.20.0-bookworm-slim@"
    "sha256:c385ec44d77c785e2364ac0c9b150809a0fdc17fde3dbf061e3dad07242c6a85"
)
AGENT_BUILDER_BASE_INDEX_DIGEST = (
    "sha256:b21fe589dfbe5cc39365d0544b9be3f1f33f55f3c86c87a76ff65a02f8f5848e"
)
CODEX_PACKAGE = "@openai/codex"
CODEX_VERSION = "0.159.2"
CODEX_INTEGRITY = (
    "sha512-SE13C3nZCYoVL569BdegoOl6vwjb7o2sXOo7ivwVzaVoY0cswwi0/6pIE0TyO/C0vIkQh3jslExitET7PBTfIg=="
)
CODEX_LINUX_X64_VERSION = "0.159.2-linux-x64"
CODEX_LINUX_X64_INTEGRITY = (
    "sha512-RrCZ1X52wpa1lOsXtCtSyhjOFdQPh7LH5Ccv8HsKmd/2UXbUwxXFqWXFK3JzatquUNGtW/TLox5Y7qVOGkV0/Q=="
)
EXPECTED_CREDENTIAL_ENV = "CODEX_API_KEY"
GATEWAY_REVIEWED_IMAGE_DIGEST = "sha256:3b4973229f7644c840fa9dee12c291bff2cf9997bcb4d320e29ce10ee5e72852"
AGENT_REVIEWED_IMAGE_DIGEST = "sha256:068b58c810869c5db4b044a9a816466dbee0a0f54902a90da83285692f0a7e0f"
VULNERABILITY_EXCEPTION_MANIFEST = Path("runtime-images/vulnerability-exceptions.json")
FIXED_GATEWAY_UID = 65532
FIXED_AGENT_UID = 10001
PLACEHOLDER_REPOSITORY = "ghcr.io/richinmrudul/agentguard"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY_DIGEST = re.compile(r"^[a-z0-9./:_-]+@sha256:[0-9a-f]{64}$")


class RuntimeImageError(ValueError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_digest(data: object) -> str:
    payload = json.dumps(data, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return "sha256:" + sha256_bytes(payload.encode("utf-8"))


def canonical_rootfs_digest(rootfs_tar: Path) -> str:
    entries: list[dict[str, Any]] = []
    try:
        with tarfile.open(rootfs_tar, "r:*") as archive:
            members = sorted(archive.getmembers(), key=lambda item: item.name)
            for member in members:
                entry: dict[str, Any] = {
                    "name": member.name,
                    "type": _tar_member_type(member),
                    "mode": member.mode,
                    "uid": member.uid,
                    "gid": member.gid,
                    "linkname": member.linkname,
                    "size": member.size if member.isfile() else 0,
                }
                if member.isfile():
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise RuntimeImageError(f"missing tar payload for {member.name}")
                    entry["sha256"] = sha256_bytes(stream.read())
                entries.append(entry)
    except (OSError, tarfile.TarError) as error:
        raise RuntimeImageError(f"invalid rootfs tar: {rootfs_tar}: {error}") from error
    if not entries:
        raise RuntimeImageError("rootfs tar must not be empty")
    return canonical_json_digest({"entries": entries})


def canonical_runtime_config(inspect_data: object) -> dict[str, Any]:
    if not isinstance(inspect_data, list) or len(inspect_data) != 1:
        raise RuntimeImageError("docker inspect JSON must contain exactly one image")
    image = _mapping(inspect_data[0], "docker inspect image")
    config = _mapping(image.get("Config"), "docker inspect Config")
    rootfs = _mapping(image.get("RootFS"), "docker inspect RootFS")
    return {
        "architecture": image.get("Architecture", ""),
        "os": image.get("Os", ""),
        "user": config.get("User", ""),
        "entrypoint": config.get("Entrypoint") or [],
        "cmd": config.get("Cmd") or [],
        "env": sorted(config.get("Env") or []),
        "working_dir": config.get("WorkingDir", ""),
        "exposed_ports": sorted((_mapping(config.get("ExposedPorts") or {}, "ExposedPorts")).keys()),
        "volumes": _volume_paths(config.get("Volumes")),
        "rootfs_type": rootfs.get("Type", ""),
    }


def canonical_runtime_identity(
    *,
    image_role: str,
    base_image: str,
    rootfs_digest: str,
    runtime_config: dict[str, Any],
) -> dict[str, Any]:
    if image_role not in {"gateway", "agent"}:
        raise RuntimeImageError("runtime identity image role must be gateway or agent")
    _image_ref(base_image, "runtime identity base image")
    _oci_digest(rootfs_digest, "runtime identity rootfs digest")
    config_digest = canonical_json_digest(runtime_config)
    identity = canonical_json_digest(
        {
            "schema": "agentguard.stage1-runtime-canonical-image-identity",
            "schema_version": 1,
            "image_role": image_role,
            "base_image": base_image,
            "rootfs_digest": rootfs_digest,
            "runtime_config_digest": config_digest,
        }
    )
    return {
        "schema": "agentguard.stage1-runtime-canonical-image-identity",
        "schema_version": 1,
        "image_role": image_role,
        "base_image": base_image,
        "identity": identity,
        "rootfs_digest": rootfs_digest,
        "runtime_config_digest": config_digest,
        "runtime_config": runtime_config,
    }


def canonical_runtime_manifest(data: dict[str, Any]) -> str:
    parsed = validate_runtime_manifest(data)
    copy = dict(parsed)
    copy.pop("canonical_manifest_digest", None)
    canonical = json.dumps(copy, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return canonical


def runtime_manifest_digest(data: dict[str, Any]) -> str:
    return sha256_bytes(canonical_runtime_manifest(data).encode("utf-8"))


def build_runtime_manifest(
    *,
    source_commit: str,
    gateway_image_digest: str,
    agent_image_digest: str,
    gateway_context_digest: str,
    agent_context_digest: str,
    sbom_digests: dict[str, str],
    provenance_digests: dict[str, str],
    scan_summaries: dict[str, Any],
    usage_evidence_status: str,
) -> dict[str, Any]:
    if not GIT_COMMIT.fullmatch(source_commit):
        raise RuntimeImageError("source commit must be a full git commit SHA")
    manifest: dict[str, Any] = {
        "schema": RUNTIME_IMAGE_MANIFEST_SCHEMA,
        "schema_version": RUNTIME_IMAGE_MANIFEST_SCHEMA_VERSION,
        "source": {
            "repository": "https://github.com/richinmrudul/agentguard",
            "commit": source_commit,
        },
        "platform": PLATFORM,
        "gateway": {
            "repository_placeholder": f"{PLACEHOLDER_REPOSITORY}/stage1-gateway",
            "oci_digest": _oci_digest(gateway_image_digest, "gateway image digest"),
            "base_image": GATEWAY_BASE_IMAGE,
            "base_index_digest": GATEWAY_BASE_INDEX_DIGEST,
            "build_context_digest": _sha256(gateway_context_digest, "gateway context digest"),
            "entrypoint": ["/agentguard-live-egress-gateway"],
            "uid": FIXED_GATEWAY_UID,
            "gid": FIXED_GATEWAY_UID,
        },
        "agent": {
            "repository_placeholder": f"{PLACEHOLDER_REPOSITORY}/stage1-codex-agent",
            "oci_digest": _oci_digest(agent_image_digest, "agent image digest"),
            "base_image": AGENT_BASE_IMAGE,
            "base_index_digest": AGENT_BASE_INDEX_DIGEST,
            "builder_base_image": AGENT_BUILDER_BASE_IMAGE,
            "builder_base_index_digest": AGENT_BUILDER_BASE_INDEX_DIGEST,
            "build_context_digest": _sha256(agent_context_digest, "agent context digest"),
            "entrypoint": ["/usr/local/bin/agentguard-codex-entrypoint"],
            "uid": FIXED_AGENT_UID,
            "gid": FIXED_AGENT_UID,
            "credential_env": EXPECTED_CREDENTIAL_ENV,
            "codex": {
                "package": CODEX_PACKAGE,
                "version": CODEX_VERSION,
                "integrity": CODEX_INTEGRITY,
                "linux_x64_version": CODEX_LINUX_X64_VERSION,
                "linux_x64_integrity": CODEX_LINUX_X64_INTEGRITY,
            },
        },
        "permitted_runtime_behavior": {
            "network": "agent reaches approved mock/provider destination only through gateway",
            "root_filesystem": "read-only with bounded tmpfs",
            "capabilities": "drop all",
            "privilege": "no-new-privileges",
            "docker_socket": "forbidden",
            "host_namespaces": "forbidden",
            "runtime_install_or_update": "forbidden",
        },
        "artifacts": {
            "sbom": _digest_mapping(sbom_digests, "sbom"),
            "provenance": _digest_mapping(provenance_digests, "provenance"),
            "scans": scan_summaries,
        },
        "usage_evidence": {
            "status": _usage_status(usage_evidence_status),
            "policy": "missing malformed conflicting incomplete or unattributable usage fails closed",
        },
        "publication": {
            "status": "not_published_phase_1",
            "registry_verification": "deferred_to_phase_2",
        },
    }
    manifest["canonical_manifest_digest"] = runtime_manifest_digest(manifest)
    return validate_runtime_manifest(manifest)


def validate_runtime_manifest(data: object) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise RuntimeImageError("runtime manifest must be an object")
    if data.get("schema") != RUNTIME_IMAGE_MANIFEST_SCHEMA:
        raise RuntimeImageError("invalid runtime manifest schema")
    if data.get("schema_version") != RUNTIME_IMAGE_MANIFEST_SCHEMA_VERSION:
        raise RuntimeImageError("unsupported runtime manifest version")
    if data.get("platform") != PLATFORM:
        raise RuntimeImageError("runtime manifest platform must be linux/amd64")
    source = _mapping(data.get("source"), "source")
    _git_commit(source.get("commit"), "source commit")
    gateway = _mapping(data.get("gateway"), "gateway")
    agent = _mapping(data.get("agent"), "agent")
    _image_ref(gateway.get("base_image"), "gateway base image")
    _image_ref(agent.get("base_image"), "agent base image")
    _image_ref(agent.get("builder_base_image"), "agent builder base image")
    _oci_digest(gateway.get("oci_digest"), "gateway oci digest")
    _oci_digest(agent.get("oci_digest"), "agent oci digest")
    if gateway.get("uid") != FIXED_GATEWAY_UID or gateway.get("gid") != FIXED_GATEWAY_UID:
        raise RuntimeImageError("gateway uid/gid mismatch")
    if agent.get("uid") != FIXED_AGENT_UID or agent.get("gid") != FIXED_AGENT_UID:
        raise RuntimeImageError("agent uid/gid mismatch")
    if agent.get("credential_env") != EXPECTED_CREDENTIAL_ENV:
        raise RuntimeImageError("agent credential environment mismatch")
    codex = _mapping(agent.get("codex"), "agent.codex")
    expected = {
        "package": CODEX_PACKAGE,
        "version": CODEX_VERSION,
        "integrity": CODEX_INTEGRITY,
        "linux_x64_version": CODEX_LINUX_X64_VERSION,
        "linux_x64_integrity": CODEX_LINUX_X64_INTEGRITY,
    }
    if codex != expected:
        raise RuntimeImageError("Codex package identity mismatch")
    if _mapping(data.get("publication"), "publication").get("status") != "not_published_phase_1":
        raise RuntimeImageError("Phase 1 manifest must not claim publication")
    scans = _mapping(_mapping(data.get("artifacts"), "artifacts").get("scans"), "artifacts.scans")
    vulnerability_policy = _mapping(
        scans.get("vulnerability_policy"),
        "artifacts.scans.vulnerability_policy",
    )
    if vulnerability_policy.get("scanner_failures_suppressed") is not False:
        raise RuntimeImageError("scanner failures must not be suppressed")
    digest = data.get("canonical_manifest_digest")
    if digest is not None and digest != runtime_manifest_digest(dict(data, canonical_manifest_digest=None)):
        raise RuntimeImageError("runtime manifest canonical digest mismatch")
    return data


def runtime_image_context_digest(path: Path) -> str:
    root = path.resolve()
    items: list[tuple[str, str]] = []
    for file_path in sorted(item for item in root.rglob("*") if item.is_file()):
        rel = file_path.relative_to(root).as_posix()
        if ".git" in file_path.parts:
            continue
        items.append((rel, sha256_bytes(file_path.read_bytes())))
    payload = json.dumps(items, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return sha256_bytes(payload.encode("utf-8"))


def parse_codex_usage(payload: object, *, trial_id: str) -> dict[str, int]:
    if not isinstance(payload, dict) or payload.get("trial_id") != trial_id:
        raise RuntimeImageError("usage evidence is not attributable to the trial")
    usage = payload.get("usage")
    if not isinstance(usage, dict) or not usage:
        raise RuntimeImageError("usage evidence is missing")
    result: dict[str, int] = {}
    for key in ("input_tokens", "output_tokens", "reasoning_tokens", "tool_tokens"):
        value = usage.get(key, 0)
        if not isinstance(value, int) or value < 0 or value > 10**9:
            raise RuntimeImageError("usage evidence is malformed")
        result[key] = value
    if result["input_tokens"] == 0 and result["output_tokens"] == 0:
        raise RuntimeImageError("usage evidence is incomplete")
    if payload.get("complete") is not True:
        raise RuntimeImageError("usage evidence is incomplete")
    return result


def summarize_trivy_high_critical(paths: list[Path]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "status": "hosted_trivy_high_critical_policy_passed",
        "severity_counts": {"CRITICAL": 0, "HIGH": 0},
        "fixability_counts": {
            "fixed": {"CRITICAL": 0, "HIGH": 0},
            "unfixed": {"CRITICAL": 0, "HIGH": 0},
        },
        "scanner_failures_suppressed": False,
        "findings": [],
    }
    for path in paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeImageError(f"invalid Trivy JSON: {path}: {error}") from error
        results = data.get("Results")
        if not isinstance(results, list) or not results:
            raise RuntimeImageError(f"Trivy JSON has no results: {path}")
        image = path.name.removesuffix(".trivy.json")
        for result in results:
            if not isinstance(result, dict):
                raise RuntimeImageError(f"Trivy result must be an object: {path}")
            vulnerabilities = result.get("Vulnerabilities")
            if vulnerabilities is None:
                continue
            if not isinstance(vulnerabilities, list):
                raise RuntimeImageError(f"Trivy vulnerabilities must be a list: {path}")
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    raise RuntimeImageError(f"Trivy vulnerability must be an object: {path}")
                severity = vulnerability.get("Severity")
                if severity not in {"HIGH", "CRITICAL"}:
                    continue
                fixed_version = vulnerability.get("FixedVersion") or ""
                fixability = "fixed" if fixed_version else "unfixed"
                summary["severity_counts"][severity] += 1
                summary["fixability_counts"][fixability][severity] += 1
                summary["findings"].append(
                    {
                        "image": image,
                        "target": result.get("Target", ""),
                        "package_type": result.get("Type", ""),
                        "package_name": vulnerability.get("PkgName", ""),
                        "installed_version": vulnerability.get("InstalledVersion", ""),
                        "vulnerability_id": vulnerability.get("VulnerabilityID", ""),
                        "severity": severity,
                        "fixed_version": fixed_version,
                        "fix_available": bool(fixed_version),
                        "package_path": vulnerability.get("PkgPath", ""),
                        "layer_digest": (vulnerability.get("Layer") or {}).get("Digest", ""),
                    }
                )
    counts = summary["severity_counts"]
    if counts["CRITICAL"] or counts["HIGH"]:
        summary["status"] = "hosted_trivy_high_critical_policy_failed"
    return summary



def evaluate_trivy_high_critical_policy(
    paths: list[Path],
    *,
    exception_manifest: Path,
    gateway_image_digest: str,
    agent_image_digest: str,
    as_of: date | None = None,
) -> dict[str, Any]:
    summary = summarize_trivy_high_critical(paths)
    _oci_digest(gateway_image_digest, "gateway image digest")
    _oci_digest(agent_image_digest, "agent image digest")
    exceptions = load_vulnerability_exceptions(
        exception_manifest,
        gateway_image_digest=gateway_image_digest,
        as_of=as_of or date.today(),
    )
    allowed = {key: item for item in exceptions for key in item["keys"]}
    matched: set[tuple[str, str, str]] = set()
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for finding in summary["findings"]:
        image = finding["image"]
        severity = finding["severity"]
        if image == "agent":
            rejected.append(dict(finding, reason="agent exceptions are forbidden"))
            continue
        if image != "gateway":
            rejected.append(dict(finding, reason="unknown image role"))
            continue
        if severity == "CRITICAL":
            rejected.append(dict(finding, reason="critical vulnerabilities are forbidden"))
            continue
        if finding["fix_available"]:
            rejected.append(dict(finding, reason="fixable high vulnerabilities require remediation"))
            continue
        key = (
            finding["vulnerability_id"],
            finding["package_name"],
            finding["installed_version"],
        )
        if key not in allowed:
            rejected.append(dict(finding, reason="unmatched gateway high vulnerability"))
            continue
        accepted.append(
            dict(
                finding,
                exception_id=allowed[key]["id"],
                gateway_image_digest=gateway_image_digest,
                gateway_base_image=GATEWAY_BASE_IMAGE,
            )
        )
        matched.add(key)
    stale = sorted(set(allowed) - matched)
    if stale:
        for cve, package, installed in stale:
            rejected.append(
                {
                    "image": "gateway",
                    "vulnerability_id": cve,
                    "package_name": package,
                    "installed_version": installed,
                    "severity": "HIGH",
                    "reason": "stale exception does not match a current scan finding",
                }
            )
    policy = dict(summary)
    policy["accepted_exceptions"] = accepted
    policy["rejected_findings"] = rejected
    policy["exception_manifest"] = str(exception_manifest)
    policy["exception_count"] = len(exceptions)
    policy["accepted_exception_count"] = len(accepted)
    policy["gateway_image_digest"] = gateway_image_digest
    policy["agent_image_digest"] = agent_image_digest
    policy["gateway_base_image"] = GATEWAY_BASE_IMAGE
    if rejected:
        policy["status"] = "hosted_trivy_high_critical_policy_failed"
    else:
        policy["status"] = "hosted_trivy_high_critical_policy_passed"
    return policy


def load_vulnerability_exceptions(
    path: Path,
    *,
    gateway_image_digest: str,
    as_of: date,
) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeImageError(f"invalid vulnerability exception manifest: {path}: {error}") from error
    if not isinstance(data, dict):
        raise RuntimeImageError("vulnerability exception manifest must be an object")
    if data.get("schema") != "agentguard.stage1-runtime-vulnerability-exceptions":
        raise RuntimeImageError("invalid vulnerability exception manifest schema")
    if data.get("schema_version") != 1:
        raise RuntimeImageError("unsupported vulnerability exception manifest version")
    if data.get("gateway_image_digest") != gateway_image_digest:
        raise RuntimeImageError("gateway image digest does not match reviewed exceptions")
    if data.get("gateway_base_image") != GATEWAY_BASE_IMAGE:
        raise RuntimeImageError("gateway base image does not match reviewed exceptions")
    if data.get("agent_image_digest") == gateway_image_digest:
        raise RuntimeImageError("exception manifest image identities are ambiguous")
    exceptions = data.get("exceptions")
    if not isinstance(exceptions, list) or not exceptions:
        raise RuntimeImageError("vulnerability exceptions are required")
    result: list[dict[str, Any]] = []
    seen_cves: set[str] = set()
    seen_keys: set[tuple[str, str, str]] = set()
    for index, item in enumerate(exceptions):
        label = f"exception[{index}]"
        if not isinstance(item, dict):
            raise RuntimeImageError(f"{label} must be an object")
        cve = _required_string(item, "cve", label)
        if not cve.startswith("CVE-") or "*" in cve:
            raise RuntimeImageError(f"{label} must use an exact CVE")
        if cve in seen_cves:
            raise RuntimeImageError(f"duplicate exception CVE: {cve}")
        seen_cves.add(cve)
        if item.get("severity") != "HIGH":
            raise RuntimeImageError(f"{label} severity must be HIGH")
        if item.get("image_role") != "gateway":
            raise RuntimeImageError(f"{label} may only apply to the gateway image")
        if item.get("gateway_image_digest") != gateway_image_digest:
            raise RuntimeImageError(f"{label} gateway image digest mismatch")
        if item.get("gateway_base_image") != GATEWAY_BASE_IMAGE:
            raise RuntimeImageError(f"{label} gateway base image mismatch")
        if item.get("owner") != "#310 maintainer":
            raise RuntimeImageError(f"{label} owner mismatch")
        approval = _date(_required_string(item, "approval_date", label), f"{label} approval date")
        expiry = _date(_required_string(item, "expiry_date", label), f"{label} expiry date")
        if approval > as_of:
            raise RuntimeImageError(f"{label} approval date is in the future")
        if expiry < as_of:
            raise RuntimeImageError(f"{label} exception expired")
        for field in ("reachability", "evidence", "compensating_controls"):
            value = item.get(field)
            if not isinstance(value, str) or not value.strip() or "*" in value:
                raise RuntimeImageError(f"{label} {field} is required")
        if item["reachability"] not in {
            "reachable",
            "plausibly reachable",
            "present but demonstrably unreachable",
            "scanner/package ambiguity",
            "unknown",
        }:
            raise RuntimeImageError(f"{label} reachability classification is invalid")
        references = item.get("advisory_references")
        if not isinstance(references, list) or not references:
            raise RuntimeImageError(f"{label} advisory references are required")
        for reference in references:
            if not isinstance(reference, str) or not reference.startswith("https://") or "*" in reference:
                raise RuntimeImageError(f"{label} advisory references must be exact HTTPS URLs")
        triggers = item.get("reevaluation_triggers")
        if not isinstance(triggers, list) or not triggers:
            raise RuntimeImageError(f"{label} reevaluation triggers are required")
        packages = item.get("affected_packages")
        if not isinstance(packages, list) or not packages:
            raise RuntimeImageError(f"{label} affected packages are required")
        keys: list[tuple[str, str, str]] = []
        for package in packages:
            if not isinstance(package, dict):
                raise RuntimeImageError(f"{label} affected package must be an object")
            name = _required_string(package, "name", label)
            installed = _required_string(package, "installed_version", label)
            if "*" in name or "*" in installed:
                raise RuntimeImageError(f"{label} affected package must be exact")
            key = (cve, name, installed)
            if key in seen_keys:
                raise RuntimeImageError(f"duplicate exception package key: {cve} {name} {installed}")
            seen_keys.add(key)
            keys.append(key)
        result.append(dict(item, id=cve, keys=keys))
    return result


def _required_string(item: dict[str, Any], key: str, label: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeImageError(f"{label} {key} is required")
    return value


def _date(value: str, label: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise RuntimeImageError(f"{label} must be YYYY-MM-DD") from error


def _tar_member_type(member: tarfile.TarInfo) -> str:
    if member.isfile():
        return "file"
    if member.isdir():
        return "directory"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    if member.ischr():
        return "char"
    if member.isblk():
        return "block"
    if member.isfifo():
        return "fifo"
    return "other"


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeImageError(f"{label} must be an object")
    return value


def _volume_paths(value: object) -> list[str]:
    if value is None:
        return []
    volumes = _mapping(value, "Config.Volumes")
    paths = []
    for path, options in volumes.items():
        if not isinstance(path, str):
            raise RuntimeImageError("Config.Volumes path must be a string")
        if (
            not path.startswith("/")
            or path != posixpath.normpath(path)
            or any(ord(character) < 32 or ord(character) == 127 for character in path)
        ):
            raise RuntimeImageError("Config.Volumes path must be an absolute normalized container path")
        if not isinstance(options, dict):
            raise RuntimeImageError("Config.Volumes options must be an object")
        paths.append(path)
    return sorted(set(paths))


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise RuntimeImageError(f"{label} must be a sha256 hex digest")
    return value


def _git_commit(value: object, label: str) -> str:
    if not isinstance(value, str) or GIT_COMMIT.fullmatch(value) is None:
        raise RuntimeImageError(f"{label} must be a full git commit SHA")
    return value


def _oci_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or OCI_DIGEST.fullmatch(value) is None:
        raise RuntimeImageError(f"{label} must be an OCI sha256 digest")
    return value


def _image_ref(value: object, label: str) -> str:
    if not isinstance(value, str) or REPOSITORY_DIGEST.fullmatch(value) is None:
        raise RuntimeImageError(f"{label} must be pinned by digest")
    return value


def _digest_mapping(value: dict[str, str], label: str) -> dict[str, str]:
    if not isinstance(value, dict) or not value:
        raise RuntimeImageError(f"{label} digests are required")
    return {str(key): _sha256(item, f"{label} digest") for key, item in sorted(value.items())}


def _usage_status(value: str) -> str:
    if value not in {"mock_supported", "USAGE_EVIDENCE_BLOCKED"}:
        raise RuntimeImageError("unsupported usage evidence status")
    return value
