from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

from agentguard.evaluation.runtime_images import (
    AGENT_BASE_IMAGE,
    AGENT_REVIEWED_IMAGE_DIGEST,
    GATEWAY_BASE_IMAGE,
    GATEWAY_REVIEWED_IMAGE_DIGEST,
    VULNERABILITY_EXCEPTION_MANIFEST,
    RuntimeImageError,
)
from scripts.stage1_publication_manifest import (
    AGENT_REPOSITORY,
    GATEWAY_REPOSITORY,
    build_prepare_manifest,
    build_post_pull_scan_bindings,
    ensure_not_rejected_publications,
    load_rejected_publications,
    normalized_sbom_package_rows,
    validate_post_publish,
    validate_post_pull_scan_bindings,
    verify_archive_boundary,
)


ROOT = Path(__file__).resolve().parents[2]
COMMIT = "85bc3fc4305c5355215c58547b2d2ca1568e9248"
GATEWAY_POST_DIGEST = "sha256:" + "a" * 64
AGENT_POST_DIGEST = "sha256:" + "b" * 64
FIRST_REJECTED_GATEWAY = (
    "sha256:fbe729bf8768fba3c68e4f8ed7eff45eb34ab814745dd7a78a9a65e7e27000a0"
)
FIRST_REJECTED_AGENT = (
    "sha256:07266c6012e9b5d36c295a0ea0d1a7570c97ccbe6332ff8e9d1da1911c496d94"
)
SECOND_REJECTED_GATEWAY = (
    "sha256:8d8b30618ec0b9b9458f5f54269432e3b48ccf29dc005676a4f53e01bef0cbf4"
)
SECOND_REJECTED_AGENT = (
    "sha256:337cf49d6283639ff6fdcd2839c4b7cc77e3a83e96c710567e1d1baf30f389da"
)


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
        (ROOT / VULNERABILITY_EXCEPTION_MANIFEST).read_text(
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


def _scan(
    target: str,
    findings: list[dict[str, str]],
    *,
    artifact_name: str | None = None,
) -> dict:
    result = {"Target": target, "Type": "debian"}
    if findings:
        result["Vulnerabilities"] = findings
    scan = {
        "SchemaVersion": 2,
        "CreatedAt": "2026-10-11T00:00:00Z",
        "Results": [result],
    }
    if artifact_name is not None:
        scan["ArtifactName"] = artifact_name
    return scan


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


def _write_scan_bindings(
    root: Path,
    post: Path,
    *,
    gateway_digest: str = GATEWAY_POST_DIGEST,
    agent_digest: str = AGENT_POST_DIGEST,
) -> dict:
    bindings = build_post_pull_scan_bindings(
        root=root,
        post_root=post,
        gateway_digest=gateway_digest,
        agent_digest=agent_digest,
    )
    _write_json(post / "scan-bindings.json", bindings)
    return bindings


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
        "HIGH": 26,
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
    _write_scan_bindings(root, post)

    with pytest.raises(RuntimeImageError, match="gateway post-publication SBOM package rows mismatch"):
        validate_post_publish(
            root=root,
            post_root=post,
            gateway_digest=GATEWAY_POST_DIGEST,
            agent_digest=AGENT_POST_DIGEST,
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
    _write_scan_bindings(root, post)

    with pytest.raises(RuntimeImageError, match="agent post-publication SBOM package rows mismatch"):
        validate_post_publish(
            root=root,
            post_root=post,
            gateway_digest=GATEWAY_POST_DIGEST,
            agent_digest=AGENT_POST_DIGEST,
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
    _write_scan_bindings(root, post)

    with pytest.raises(RuntimeImageError, match="gateway post-publication SBOM package rows mismatch"):
        validate_post_publish(
            root=root,
            post_root=post,
            gateway_digest=GATEWAY_POST_DIGEST,
            agent_digest=AGENT_POST_DIGEST,
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
    _write_scan_bindings(root, post)

    with pytest.raises(RuntimeImageError, match="gateway pulled digest"):
        validate_post_publish(
            root=root,
            post_root=post,
            gateway_digest=GATEWAY_POST_DIGEST,
            agent_digest=AGENT_POST_DIGEST,
        )


def test_post_publish_validation_accepts_explicit_pulled_scan_role_bindings(
    tmp_path: Path,
) -> None:
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
    _write_json(post / "agent.pulled.sbom.json", _sbom(5))
    _write_json(
        post / "gateway.pulled.trivy.json",
        _scan(
            "/work/gateway-pulled-image.tar",
            _reviewed_gateway_findings(),
            artifact_name=f"{GATEWAY_REPOSITORY}@{GATEWAY_POST_DIGEST}",
        ),
    )
    _write_json(
        post / "agent.pulled.trivy.json",
        _scan(
            "/work/agent-pulled-image.tar",
            [],
            artifact_name=f"{AGENT_REPOSITORY}@{AGENT_POST_DIGEST}",
        ),
    )
    _write_scan_bindings(root, post)

    validate_post_publish(
        root=root,
        post_root=post,
        gateway_digest=GATEWAY_POST_DIGEST,
        agent_digest=AGENT_POST_DIGEST,
    )


@pytest.mark.parametrize(
    "mutate,match",
    [
        (
            lambda data: data["scans"][0].__setitem__("role", "other"),
            "unknown role",
        ),
        (
            lambda data: data["scans"].pop(),
            "missing post-pull scan role",
        ),
        (
            lambda data: data["scans"].append(dict(data["scans"][0])),
            "duplicate post-pull scan role",
        ),
        (
            lambda data: data["scans"][0].__setitem__("repository", AGENT_REPOSITORY),
            "gateway post-pull repository mismatch",
        ),
        (
            lambda data: data["scans"][0].__setitem__("digest", "sha256:" + "9" * 64),
            "gateway post-pull digest mismatch",
        ),
        (
            lambda data: data["scans"][0].__setitem__(
                "pulled_reference", f"{GATEWAY_REPOSITORY}:latest"
            ),
            "gateway post-pull reference must be immutable",
        ),
        (
            lambda data: data["scans"][0].__setitem__("prepared_archive_role", "agent"),
            "gateway prepared archive role mismatch",
        ),
        (
            lambda data: data["scans"][0].__setitem__("scan_path", "gateway.trivy.json"),
            "gateway scan path mismatch",
        ),
    ],
)
def test_post_pull_scan_bindings_fail_closed(
    tmp_path: Path,
    mutate,
    match: str,
) -> None:
    root = _root(tmp_path)
    _write_json(root / "publication-manifest.json", _manifest(root))
    post = tmp_path / "post"
    post.mkdir()
    _write_json(post / "gateway.pulled.trivy.json", _scan("gateway", []))
    _write_json(post / "agent.pulled.trivy.json", _scan("agent", []))
    bindings = _write_scan_bindings(root, post)
    mutate(bindings)
    _write_json(post / "scan-bindings.json", bindings)

    with pytest.raises(RuntimeImageError, match=match):
        validate_post_pull_scan_bindings(
            root=root,
            post_root=post,
            gateway_digest=GATEWAY_POST_DIGEST,
            agent_digest=AGENT_POST_DIGEST,
        )


def test_post_pull_scan_binding_rejects_artifact_reference_mismatch(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    _write_json(root / "publication-manifest.json", _manifest(root))
    post = tmp_path / "post"
    post.mkdir()
    _write_json(
        post / "gateway.pulled.trivy.json",
        _scan(
            "gateway",
            [],
            artifact_name=f"{AGENT_REPOSITORY}@{GATEWAY_POST_DIGEST}",
        ),
    )
    _write_json(post / "agent.pulled.trivy.json", _scan("agent", []))

    with pytest.raises(RuntimeImageError, match="gateway scan artifact reference mismatch"):
        _write_scan_bindings(root, post)


def test_gateway_exceptions_cannot_apply_to_agent_with_explicit_binding(
    tmp_path: Path,
) -> None:
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
    _write_json(post / "agent.pulled.sbom.json", _sbom(5))
    _write_json(post / "gateway.pulled.trivy.json", _scan("gateway", []))
    _write_json(post / "agent.pulled.trivy.json", _scan("agent", _reviewed_gateway_findings()))
    _write_scan_bindings(root, post)

    with pytest.raises(RuntimeImageError, match="post-publication vulnerability policy failed"):
        validate_post_publish(
            root=root,
            post_root=post,
            gateway_digest=GATEWAY_POST_DIGEST,
            agent_digest=AGENT_POST_DIGEST,
        )


def test_rejected_publications_record_failed_publication_digests() -> None:
    rejected = load_rejected_publications()
    keys = {(item["role"], item["repository"], item["digest"]) for item in rejected}

    assert ("gateway", GATEWAY_REPOSITORY, FIRST_REJECTED_GATEWAY) in keys
    assert ("agent", AGENT_REPOSITORY, FIRST_REJECTED_AGENT) in keys
    assert ("gateway", GATEWAY_REPOSITORY, SECOND_REJECTED_GATEWAY) in keys
    assert ("agent", AGENT_REPOSITORY, SECOND_REJECTED_AGENT) in keys
    assert all(item["status"] == "rejected" for item in rejected)
    assert all(item["eligible_for_study"] is False for item in rejected)
    assert all(
        item["failure_stage"]
        in {"post-publication evidence policy", "post_pull_mock_integration"}
        for item in rejected
    )


def test_rejected_publication_candidates_fail_but_unrelated_digest_passes() -> None:
    for role, repository, digest in (
        ("gateway", GATEWAY_REPOSITORY, FIRST_REJECTED_GATEWAY),
        ("agent", AGENT_REPOSITORY, FIRST_REJECTED_AGENT),
        ("gateway", GATEWAY_REPOSITORY, SECOND_REJECTED_GATEWAY),
        ("agent", AGENT_REPOSITORY, SECOND_REJECTED_AGENT),
    ):
        candidates = {
            "gateway": (GATEWAY_REPOSITORY, GATEWAY_POST_DIGEST),
            "agent": (AGENT_REPOSITORY, AGENT_POST_DIGEST),
        }
        candidates[role] = (repository, digest)
        with pytest.raises(
            RuntimeImageError,
            match=f"{role} published digest is recorded as rejected",
        ):
            ensure_not_rejected_publications(candidates)

    ensure_not_rejected_publications(
        {
            "gateway": (AGENT_REPOSITORY, FIRST_REJECTED_GATEWAY),
            "agent": (GATEWAY_REPOSITORY, FIRST_REJECTED_AGENT),
        }
    )

    ensure_not_rejected_publications(
        {
            "gateway": (GATEWAY_REPOSITORY, GATEWAY_POST_DIGEST),
            "agent": (AGENT_REPOSITORY, AGENT_POST_DIGEST),
        }
    )


@pytest.mark.parametrize(
    "mutate,match",
    [
        (
            lambda data: data.__setitem__("schema", "wrong"),
            "invalid rejected-publications schema",
        ),
        (
            lambda data: data["rejected_publications"].append(
                dict(data["rejected_publications"][0])
            ),
            "duplicate rejected publication",
        ),
        (
            lambda data: data["rejected_publications"][0].__setitem__(
                "status", "approved"
            ),
            "status must be rejected",
        ),
        (
            lambda data: data["rejected_publications"][0].__setitem__(
                "eligible_for_study", True
            ),
            "must not be study eligible",
        ),
        (
            lambda data: data["rejected_publications"][0].__setitem__(
                "repository", AGENT_REPOSITORY
            ),
            "repository mismatch",
        ),
    ],
)
def test_rejected_publication_record_schema_fails_closed(
    tmp_path: Path,
    mutate,
    match: str,
) -> None:
    data = json.loads((ROOT / "runtime-images/rejected-publications.json").read_text())
    mutate(data)
    path = tmp_path / "rejected-publications.json"
    _write_json(path, data)

    with pytest.raises(RuntimeImageError, match=match):
        load_rejected_publications(path)
