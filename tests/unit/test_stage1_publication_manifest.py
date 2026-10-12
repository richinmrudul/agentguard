import json
import hashlib
from pathlib import Path

import pytest

from agentguard.evaluation.runtime_images import (
    AGENT_BASE_IMAGE,
    AGENT_REVIEWED_IMAGE_DIGEST,
    GATEWAY_BASE_IMAGE,
    GATEWAY_REVIEWED_IMAGE_DIGEST,
    RuntimeImageError,
)
from scripts.stage1_publication_manifest import (
    AGENT_REPOSITORY,
    GATEWAY_REPOSITORY,
    build_prepare_manifest,
    normalized_sbom_package_rows,
    validate_post_publish,
    verify_archive_boundary,
)


ROOT = Path(__file__).resolve().parents[2]
COMMIT = "85bc3fc4305c5355215c58547b2d2ca1568e9248"


def _write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, sort_keys=True) + "\n", encoding="utf-8")


def _identity(role: str, digest: str, base: str) -> dict:
    return {
        "schema": "agentguard.stage1-runtime-canonical-image-identity",
        "schema_version": 1,
        "image_role": role,
        "base_image": base,
        "identity": digest,
        "rootfs_digest": "sha256:" + ("1" if role == "gateway" else "2") * 64,
        "runtime_config_digest": "sha256:" + ("3" if role == "gateway" else "4") * 64,
        "runtime_config": {
            "architecture": "amd64",
            "os": "linux",
            "user": "65532:65532" if role == "gateway" else "10001:10001",
            "entrypoint": ["/entrypoint"],
            "cmd": [],
            "env": [],
            "working_dir": "/",
            "exposed_ports": [],
            "volumes": [],
            "rootfs_type": "layers",
        },
    }


def _sbom(count: int) -> dict:
    return {
        "artifacts": [
            {
                "type": "deb",
                "name": f"package-{index}",
                "version": "1",
                "purl": f"pkg:deb/package-{index}@1",
                "licenses": [{"value": "MIT"}],
            }
            for index in range(count)
        ]
    }


def _reviewed_gateway_findings() -> list[dict[str, str]]:
    manifest = json.loads(
        (ROOT / "runtime-images/vulnerability-exceptions.json").read_text(
            encoding="utf-8"
        )
    )
    findings = []
    for exception in manifest["exceptions"]:
        for package in exception["affected_packages"]:
            findings.append(
                {
                    "VulnerabilityID": exception["cve"],
                    "PkgName": package["name"],
                    "InstalledVersion": package["installed_version"],
                    "Severity": "HIGH",
                }
            )
    return findings


def _scan(target: str, findings: list[dict[str, str]]) -> dict:
    result = {"Target": target, "Type": "debian"}
    if findings:
        result["Vulnerabilities"] = findings
    return {
        "SchemaVersion": 2,
        "CreatedAt": "2026-10-11T00:00:00Z",
        "Results": [result],
    }


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "publication"
    root.mkdir()
    _write_json(
        root / "gateway.identity.json",
        _identity("gateway", GATEWAY_REVIEWED_IMAGE_DIGEST, GATEWAY_BASE_IMAGE),
    )
    _write_json(
        root / "agent.identity.json",
        _identity("agent", AGENT_REVIEWED_IMAGE_DIGEST, AGENT_BASE_IMAGE),
    )
    _write_json(root / "gateway.sbom.json", _sbom(38))
    _write_json(root / "agent.sbom.json", _sbom(5))
    _write_json(root / "gateway.trivy.json", _scan("gateway", _reviewed_gateway_findings()))
    _write_json(root / "agent.trivy.json", _scan("agent", []))
    _write_json(
        root / "trivy-db-metadata.json",
        {
            "Version": 2,
            "UpdatedAt": "2026-10-11T00:00:00Z",
            "DownloadedAt": "2026-10-11T00:00:00Z",
        },
    )
    (root / "trivy-version.txt").write_text("Version: 0.67.2\n", encoding="utf-8")
    (root / "mock-provider-integration.txt").write_text(
        "mock-provider-gateway-runtime-ok\ncodex-cli 0.159.2\n",
        encoding="utf-8",
    )
    (root / "gateway-image.tar").write_text("gateway archive\n", encoding="utf-8")
    (root / "agent-image.tar").write_text("agent archive\n", encoding="utf-8")
    _write_checksums(root)
    return root


def _write_checksums(root: Path, *, extra: str = "") -> None:
    lines = []
    for name in ("gateway-image.tar", "agent-image.tar"):
        digest = hashlib.sha256((root / name).read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}")
    if extra:
        lines.append(extra)
    (root / "image-archives.SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _manifest(root: Path) -> dict:
    return build_prepare_manifest(
        root=root,
        source_commit=COMMIT,
        workflow="Publish Stage 1 Runtime Images",
        run_id="123",
        run_attempt="1",
        gateway_image=f"{GATEWAY_REPOSITORY}:{COMMIT}",
        agent_image=f"{AGENT_REPOSITORY}:{COMMIT}",
    )


def test_prepare_publication_manifest_records_reviewed_evidence(tmp_path: Path) -> None:
    root = _root(tmp_path)

    manifest = build_prepare_manifest(
        root=root,
        source_commit=COMMIT,
        workflow="Publish Stage 1 Runtime Images",
        run_id="123",
        run_attempt="1",
        gateway_image=f"{GATEWAY_REPOSITORY}:{COMMIT}",
        agent_image=f"{AGENT_REPOSITORY}:{COMMIT}",
    )

    assert manifest["schema"] == "agentguard.stage1-runtime-publication"
    assert manifest["source"]["commit"] == COMMIT
    assert manifest["platform"] == "linux/amd64"
    assert manifest["activation"]["repository_variable"] == (
        "STAGE1_RUNTIME_PUBLICATION_ENABLED"
    )
    assert manifest["images"]["gateway"]["canonical_identity"] == (
        GATEWAY_REVIEWED_IMAGE_DIGEST
    )
    assert manifest["images"]["agent"]["canonical_identity"] == (
        AGENT_REVIEWED_IMAGE_DIGEST
    )
    assert manifest["images"]["gateway"]["sbom_package_count"] == 38
    assert manifest["images"]["agent"]["sbom_package_count"] == 5
    assert manifest["images"]["gateway"]["sbom_rows_digest"].startswith("sha256:")
    assert manifest["images"]["agent"]["sbom_rows_schema"] == (
        "agentguard.stage1-runtime-sbom-package-rows.v1"
    )
    assert manifest["vulnerability_policy"]["severity_counts"] == {
        "CRITICAL": 0,
        "HIGH": 31,
    }
    assert manifest["vulnerability_policy"]["exception_expiry"] == "2026-11-06"
    assert manifest["manifest_digest"].startswith("sha256:")


def test_prepare_manifest_rejects_moving_or_short_tags(tmp_path: Path) -> None:
    root = _root(tmp_path)

    with pytest.raises(RuntimeImageError, match="full source commit tag"):
        build_prepare_manifest(
            root=root,
            source_commit=COMMIT,
            workflow="Publish Stage 1 Runtime Images",
            run_id="123",
            run_attempt="1",
            gateway_image=f"{GATEWAY_REPOSITORY}:latest",
            agent_image=f"{AGENT_REPOSITORY}:{COMMIT}",
        )


def test_prepare_manifest_rejects_unreviewed_findings(tmp_path: Path) -> None:
    root = _root(tmp_path)
    data = _scan(
        "agent",
        [
            {
                "VulnerabilityID": "CVE-2099-0001",
                "PkgName": "bad",
                "InstalledVersion": "1",
                "Severity": "HIGH",
            }
        ],
    )
    _write_json(root / "agent.trivy.json", data)

    with pytest.raises(RuntimeImageError, match="vulnerability exception policy failed"):
        build_prepare_manifest(
            root=root,
            source_commit=COMMIT,
            workflow="Publish Stage 1 Runtime Images",
            run_id="123",
            run_attempt="1",
            gateway_image=f"{GATEWAY_REPOSITORY}:{COMMIT}",
            agent_image=f"{AGENT_REPOSITORY}:{COMMIT}",
        )


def test_normalized_sbom_rows_are_order_independent() -> None:
    first = {
        "artifacts": [
            {"type": "deb", "name": "b", "version": "2", "purl": "pkg:deb/b@2"},
            {"type": "deb", "name": "a", "version": "1", "purl": "pkg:deb/a@1"},
        ]
    }
    second = {"artifacts": list(reversed(first["artifacts"]))}

    assert normalized_sbom_package_rows(first) == normalized_sbom_package_rows(second)


def test_normalized_sbom_rows_reject_malformed_packages() -> None:
    with pytest.raises(RuntimeImageError, match="missing name"):
        normalized_sbom_package_rows(
            {"artifacts": [{"type": "deb", "version": "1", "purl": "pkg:deb/a@1"}]}
        )


def test_post_publish_validation_requires_exact_sbom_rows(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _write_json(root / "publication-manifest.json", _manifest(root))
    post = tmp_path / "post"
    post.mkdir()
    _write_json(
        post / "gateway.identity.json",
        _identity("gateway", GATEWAY_REVIEWED_IMAGE_DIGEST, GATEWAY_BASE_IMAGE),
    )
    _write_json(
        post / "agent.identity.json",
        _identity("agent", AGENT_REVIEWED_IMAGE_DIGEST, AGENT_BASE_IMAGE),
    )
    gateway_sbom = _sbom(38)
    gateway_sbom["artifacts"][0]["version"] = "2"
    _write_json(post / "gateway.pulled.sbom.json", gateway_sbom)
    _write_json(post / "agent.pulled.sbom.json", _sbom(5))
    _write_json(post / "gateway.pulled.trivy.json", _scan("gateway", _reviewed_gateway_findings()))
    _write_json(post / "agent.pulled.trivy.json", _scan("agent", []))

    with pytest.raises(RuntimeImageError, match="gateway post-publication SBOM package rows mismatch"):
        validate_post_publish(
            root=root,
            post_root=post,
            gateway_digest="sha256:" + "a" * 64,
            agent_digest="sha256:" + "b" * 64,
        )


def test_post_publish_validation_rejects_count_equal_package_name_drift(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _write_json(root / "publication-manifest.json", _manifest(root))
    post = tmp_path / "post"
    post.mkdir()
    _write_json(
        post / "gateway.identity.json",
        _identity("gateway", GATEWAY_REVIEWED_IMAGE_DIGEST, GATEWAY_BASE_IMAGE),
    )
    _write_json(
        post / "agent.identity.json",
        _identity("agent", AGENT_REVIEWED_IMAGE_DIGEST, AGENT_BASE_IMAGE),
    )
    _write_json(post / "gateway.pulled.sbom.json", _sbom(38))
    agent_sbom = _sbom(5)
    agent_sbom["artifacts"][0]["name"] = "changed-package"
    _write_json(post / "agent.pulled.sbom.json", agent_sbom)
    _write_json(post / "gateway.pulled.trivy.json", _scan("gateway", _reviewed_gateway_findings()))
    _write_json(post / "agent.pulled.trivy.json", _scan("agent", []))

    with pytest.raises(RuntimeImageError, match="agent post-publication SBOM package rows mismatch"):
        validate_post_publish(
            root=root,
            post_root=post,
            gateway_digest="sha256:" + "a" * 64,
            agent_digest="sha256:" + "b" * 64,
        )


def test_post_publish_validation_rejects_added_removed_or_duplicate_package(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _write_json(root / "publication-manifest.json", _manifest(root))
    post = tmp_path / "post"
    post.mkdir()
    _write_json(
        post / "gateway.identity.json",
        _identity("gateway", GATEWAY_REVIEWED_IMAGE_DIGEST, GATEWAY_BASE_IMAGE),
    )
    _write_json(
        post / "agent.identity.json",
        _identity("agent", AGENT_REVIEWED_IMAGE_DIGEST, AGENT_BASE_IMAGE),
    )
    gateway_sbom = _sbom(38)
    gateway_sbom["artifacts"][1] = dict(gateway_sbom["artifacts"][0])
    _write_json(post / "gateway.pulled.sbom.json", gateway_sbom)
    _write_json(post / "agent.pulled.sbom.json", _sbom(4))
    _write_json(post / "gateway.pulled.trivy.json", _scan("gateway", _reviewed_gateway_findings()))
    _write_json(post / "agent.pulled.trivy.json", _scan("agent", []))

    with pytest.raises(RuntimeImageError, match="gateway post-publication SBOM package rows mismatch"):
        validate_post_publish(
            root=root,
            post_root=post,
            gateway_digest="sha256:" + "a" * 64,
            agent_digest="sha256:" + "b" * 64,
        )


def test_archive_boundary_requires_manifest_checksum_and_computed_hash_agreement(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    _write_json(root / "publication-manifest.json", _manifest(root))

    verify_archive_boundary(
        root=root,
        source_commit=COMMIT,
        gateway_image=f"{GATEWAY_REPOSITORY}:{COMMIT}",
        agent_image=f"{AGENT_REPOSITORY}:{COMMIT}",
    )

    (root / "agent-image.tar").write_text("changed archive\n", encoding="utf-8")
    with pytest.raises(RuntimeImageError, match="agent archive digest mismatch"):
        verify_archive_boundary(
            root=root,
            source_commit=COMMIT,
            gateway_image=f"{GATEWAY_REPOSITORY}:{COMMIT}",
            agent_image=f"{AGENT_REPOSITORY}:{COMMIT}",
        )


@pytest.mark.parametrize(
    "line,match",
    [
        ("not-a-checksum  gateway-image.tar", "malformed"),
        ("0" * 64 + "  ../gateway-image.tar", "invalid archive checksum filename"),
        ("0" * 64 + "  /tmp/gateway-image.tar", "invalid archive checksum filename"),
        ("0" * 64 + "  extra-image.tar", "exactly gateway and agent"),
    ],
)
def test_archive_boundary_rejects_malformed_extra_or_unsafe_checksum_entries(
    tmp_path: Path,
    line: str,
    match: str,
) -> None:
    root = _root(tmp_path)
    _write_json(root / "publication-manifest.json", _manifest(root))
    _write_checksums(root, extra=line)

    with pytest.raises(RuntimeImageError, match=match):
        verify_archive_boundary(
            root=root,
            source_commit=COMMIT,
            gateway_image=f"{GATEWAY_REPOSITORY}:{COMMIT}",
            agent_image=f"{AGENT_REPOSITORY}:{COMMIT}",
        )


def test_archive_boundary_rejects_role_swapping(tmp_path: Path) -> None:
    root = _root(tmp_path)
    manifest = _manifest(root)
    manifest["images"]["gateway"]["archive_name"] = "agent-image.tar"
    _write_json(root / "publication-manifest.json", manifest)

    with pytest.raises(RuntimeImageError, match="gateway archive filename mismatch"):
        verify_archive_boundary(
            root=root,
            source_commit=COMMIT,
            gateway_image=f"{GATEWAY_REPOSITORY}:{COMMIT}",
            agent_image=f"{AGENT_REPOSITORY}:{COMMIT}",
        )


def test_post_publish_validation_rejects_bad_pulled_identity(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _write_json(root / "publication-manifest.json", _manifest(root))
    post = tmp_path / "post"
    post.mkdir()
    _write_json(
        post / "gateway.identity.json",
        _identity("gateway", "sha256:" + "9" * 64, GATEWAY_BASE_IMAGE),
    )
    _write_json(
        post / "agent.identity.json",
        _identity("agent", AGENT_REVIEWED_IMAGE_DIGEST, AGENT_BASE_IMAGE),
    )
    _write_json(post / "gateway.pulled.sbom.json", _sbom(38))
    _write_json(post / "agent.pulled.sbom.json", _sbom(5))
    _write_json(post / "gateway.pulled.trivy.json", _scan("gateway", _reviewed_gateway_findings()))
    _write_json(post / "agent.pulled.trivy.json", _scan("agent", []))

    with pytest.raises(RuntimeImageError, match="gateway pulled digest"):
        validate_post_publish(
            root=root,
            post_root=post,
            gateway_digest="sha256:" + "a" * 64,
            agent_digest="sha256:" + "b" * 64,
        )
