import copy
import json
import tarfile
from datetime import date
import subprocess
import sys
from pathlib import Path

import pytest

from agentguard.evaluation.runtime_images import (
    AGENT_BASE_IMAGE,
    AGENT_BUILDER_BASE_IMAGE,
    CODEX_INTEGRITY,
    CODEX_LINUX_X64_INTEGRITY,
    CODEX_VERSION,
    EXPECTED_CREDENTIAL_ENV,
    GATEWAY_BASE_IMAGE,
    GATEWAY_REVIEWED_IMAGE_DIGEST,
    AGENT_REVIEWED_IMAGE_DIGEST,
    RuntimeImageError,
    build_runtime_manifest,
    canonical_rootfs_digest,
    canonical_runtime_config,
    canonical_runtime_identity,
    parse_codex_usage,
    runtime_image_context_digest,
    runtime_manifest_digest,
    evaluate_trivy_high_critical_policy,
    load_vulnerability_exceptions,
    summarize_trivy_high_critical,
    validate_runtime_manifest,
)


ROOT = Path(__file__).resolve().parents[2]


def _manifest(**changes):
    data = build_runtime_manifest(
        source_commit="0a38d29dc127b9b4a9ab67f885b2228f27fdaeaf",
        gateway_image_digest="sha256:" + "1" * 64,
        agent_image_digest="sha256:" + "2" * 64,
        gateway_context_digest="3" * 64,
        agent_context_digest="4" * 64,
        sbom_digests={"gateway": "5" * 64, "agent": "6" * 64},
        provenance_digests={"gateway": "7" * 64, "agent": "8" * 64},
        scan_summaries={
            "vulnerability_policy": {
                "status": "not_run_phase1_mock_only",
                "scanner_failures_suppressed": False,
            },
            "secret_scan": {"findings": 0},
            "license": {"review_required": False},
        },
        usage_evidence_status="mock_supported",
    )
    data.update(changes)
    return data


def test_runtime_manifest_is_canonical_and_phase1_unpublished() -> None:
    manifest = _manifest()

    assert validate_runtime_manifest(manifest) == manifest
    assert manifest["gateway"]["base_image"] == GATEWAY_BASE_IMAGE
    assert manifest["agent"]["base_image"] == AGENT_BASE_IMAGE
    assert manifest["agent"]["builder_base_image"] == AGENT_BUILDER_BASE_IMAGE
    assert manifest["agent"]["codex"]["version"] == CODEX_VERSION
    assert manifest["agent"]["codex"]["integrity"] == CODEX_INTEGRITY
    assert manifest["agent"]["codex"]["linux_x64_integrity"] == CODEX_LINUX_X64_INTEGRITY
    assert manifest["agent"]["credential_env"] == EXPECTED_CREDENTIAL_ENV
    assert manifest["publication"]["status"] == "not_published_phase_1"
    assert manifest["canonical_manifest_digest"] == runtime_manifest_digest(manifest)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("publication", "status"), "published", "must not claim publication"),
        (("agent", "credential_env"), "OPENAI_API_KEY", "credential environment"),
        (("agent", "codex", "integrity"), "sha512-bad", "Codex package identity"),
        (("gateway", "oci_digest"), "latest", "OCI sha256"),
    ],
)
def test_runtime_manifest_rejects_unsafe_or_inaccurate_fields(path, value, message) -> None:
    manifest = _manifest()
    target = manifest
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value

    with pytest.raises(RuntimeImageError, match=message):
        validate_runtime_manifest(manifest)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda data: "not-an-object", "must be an object"),
        (lambda data: dict(data, schema="wrong"), "invalid runtime manifest schema"),
        (lambda data: dict(data, schema_version=999), "unsupported runtime manifest version"),
        (lambda data: dict(data, platform="linux/arm64"), "platform must be linux/amd64"),
        (
            lambda data: dict(
                data,
                gateway=dict(data["gateway"], uid=0),
            ),
            "gateway uid/gid mismatch",
        ),
        (
            lambda data: dict(
                data,
                agent=dict(data["agent"], uid=0),
            ),
            "agent uid/gid mismatch",
        ),
        (
            lambda data: dict(
                data,
                gateway=dict(data["gateway"], base_image="python:latest"),
            ),
            "pinned by digest",
        ),
        (
            lambda data: dict(
                data,
                canonical_manifest_digest="0" * 64,
            ),
            "canonical digest mismatch",
        ),
        (
            lambda data: dict(data, artifacts=[]),
            "artifacts must be an object",
        ),
    ],
)
def test_runtime_manifest_rejects_malformed_manifest_shapes(mutate, message) -> None:
    with pytest.raises(RuntimeImageError, match=message):
        validate_runtime_manifest(mutate(_manifest()))


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"source_commit": "bad"}, "source commit"),
        ({"gateway_context_digest": "bad"}, "sha256 hex digest"),
        ({"sbom_digests": {}}, "sbom digests are required"),
        ({"usage_evidence_status": "optimistic"}, "unsupported usage evidence status"),
    ],
)
def test_runtime_manifest_builder_rejects_invalid_inputs(kwargs, message) -> None:
    params = {
        "source_commit": "0a38d29dc127b9b4a9ab67f885b2228f27fdaeaf",
        "gateway_image_digest": "sha256:" + "1" * 64,
        "agent_image_digest": "sha256:" + "2" * 64,
        "gateway_context_digest": "3" * 64,
        "agent_context_digest": "4" * 64,
        "sbom_digests": {"gateway": "5" * 64, "agent": "6" * 64},
        "provenance_digests": {"gateway": "7" * 64, "agent": "8" * 64},
        "scan_summaries": {
            "vulnerability_policy": {
                "status": "not_run_phase1_mock_only",
                "scanner_failures_suppressed": False,
            },
        },
        "usage_evidence_status": "mock_supported",
    }
    params.update(kwargs)

    with pytest.raises(RuntimeImageError, match=message):
        build_runtime_manifest(**params)


def test_runtime_manifest_rejects_suppressed_scanner_failures() -> None:
    manifest = _manifest()
    manifest["artifacts"]["scans"]["vulnerability_policy"][
        "scanner_failures_suppressed"
    ] = True

    with pytest.raises(RuntimeImageError, match="scanner failures"):
        validate_runtime_manifest(manifest)


def test_context_digest_changes_with_reviewed_build_inputs(tmp_path: Path) -> None:
    context = tmp_path / "context"
    context.mkdir()
    (context / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    first = runtime_image_context_digest(context)
    (context / "entrypoint.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    second = runtime_image_context_digest(context)

    assert first != second
    assert len(first) == 64
    assert len(second) == 64


def test_context_digest_ignores_git_metadata(tmp_path: Path) -> None:
    context = tmp_path / "context"
    git_dir = context / ".git"
    git_dir.mkdir(parents=True)
    (context / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    before = runtime_image_context_digest(context)
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

    assert runtime_image_context_digest(context) == before


def test_usage_evidence_is_attributable_bounded_and_fail_closed() -> None:
    parsed = parse_codex_usage(
        {
            "trial_id": "trial-1",
            "complete": True,
            "usage": {"input_tokens": 12, "output_tokens": 5, "reasoning_tokens": 1},
        },
        trial_id="trial-1",
    )

    assert parsed["input_tokens"] == 12
    assert parsed["output_tokens"] == 5

    for payload in [
        {"trial_id": "other", "complete": True, "usage": {"input_tokens": 1}},
        {"trial_id": "trial-1", "complete": True, "usage": {}},
        {"trial_id": "trial-1", "complete": True, "usage": {"input_tokens": -1}},
        {"trial_id": "trial-1", "complete": False, "usage": {"input_tokens": 1}},
        {"trial_id": "trial-1", "complete": True, "usage": {"input_tokens": 0, "output_tokens": 0}},
    ]:
        with pytest.raises(RuntimeImageError):
            parse_codex_usage(payload, trial_id="trial-1")


def test_runtime_image_policy_validator_and_manifest_cli(tmp_path: Path) -> None:
    output = tmp_path / "manifest.json"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/validate_runtime_images.py",
            "--source-commit",
            "0a38d29dc127b9b4a9ab67f885b2228f27fdaeaf",
            "--emit-manifest",
            str(output),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["schema"] == "agentguard.stage1-runtime-image-freeze"
    assert data["publication"]["status"] == "not_published_phase_1"


def test_codex_agent_lock_uses_exact_verified_official_integrities() -> None:
    lock = json.loads(
        (ROOT / "runtime-images/codex-agent/package-lock.json").read_text(encoding="utf-8")
    )

    codex = lock["packages"]["node_modules/@openai/codex"]
    linux = lock["packages"]["node_modules/@openai/codex-linux-x64"]
    assert codex["version"] == CODEX_VERSION
    assert codex["integrity"] == CODEX_INTEGRITY
    assert linux["version"] == "0.159.2-linux-x64"
    assert linux["integrity"] == CODEX_LINUX_X64_INTEGRITY


def test_final_runtime_dockerfiles_do_not_carry_package_managers_or_node_runtime() -> None:
    gateway = (ROOT / "runtime-images/gateway/Dockerfile").read_text(encoding="utf-8")
    agent = (ROOT / "runtime-images/codex-agent/Dockerfile").read_text(encoding="utf-8")
    agent_final = agent[agent.rfind("\nFROM ") + 1 :]

    assert GATEWAY_BASE_IMAGE in gateway
    assert AGENT_BASE_IMAGE in agent_final
    assert AGENT_BUILDER_BASE_IMAGE in agent
    assert "python:3.12" not in gateway
    assert "node:22" not in agent_final
    assert "node_modules" not in agent_final
    assert "npm" not in agent_final
    assert "apt-get" not in agent_final
    assert "codex-resources/voice" not in agent
    assert "COPY --from=codex-download /opt/codex-runtime /opt/codex" in agent_final


def test_agent_entrypoint_is_compiled_wrapper_not_shell_script() -> None:
    entrypoint = (ROOT / "runtime-images/codex-agent/entrypoint.c").read_text(encoding="utf-8")
    legacy_shell = (ROOT / "runtime-images/codex-agent/entrypoint.sh").read_text(encoding="utf-8")
    dockerfile = (ROOT / "runtime-images/codex-agent/Dockerfile").read_text(encoding="utf-8")

    assert "CODEX_API_KEY" in entrypoint
    assert "CODEX_MODEL" in entrypoint
    assert "OPENAI_API_KEY" in entrypoint
    assert "execv(\"/opt/codex/bin/codex\"" in entrypoint
    assert "entrypoint.sh" not in dockerfile
    assert "#!/bin/sh" in legacy_shell


def test_trivy_summary_rejects_invalid_or_incomplete_json(tmp_path: Path) -> None:
    empty = tmp_path / "empty.trivy.json"
    empty.write_text('{"Results":[]}\n', encoding="utf-8")

    with pytest.raises(RuntimeImageError, match="no results"):
        summarize_trivy_high_critical([empty])

    malformed = tmp_path / "malformed.trivy.json"
    malformed.write_text("{", encoding="utf-8")
    with pytest.raises(RuntimeImageError, match="invalid Trivy JSON"):
        summarize_trivy_high_critical([malformed])


def _write_rootfs_tar(path: Path, *, content: bytes = b"hello", mode: int = 0o555, uid: int = 1000) -> None:
    with tarfile.open(path, "w") as archive:
        directory = tarfile.TarInfo("app")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        directory.uid = uid
        directory.gid = uid
        archive.addfile(directory)
        file_info = tarfile.TarInfo("app/entrypoint")
        file_info.size = len(content)
        file_info.mode = mode
        file_info.uid = uid
        file_info.gid = uid
        archive.addfile(file_info, __import__("io").BytesIO(content))


def _inspect_config(
    *,
    user: str = "1000:1000",
    entrypoint=None,
    env=None,
    layers=None,
    volumes=None,
):
    config_volumes = {} if volumes is None else volumes
    return [
        {
            "Architecture": "amd64",
            "Os": "linux",
            "Config": {
                "User": user,
                "Entrypoint": entrypoint or ["/app/entrypoint"],
                "Cmd": [],
                "Env": env or ["PATH=/usr/bin"],
                "WorkingDir": "/",
                "ExposedPorts": {"8080/tcp": {}},
                "Volumes": config_volumes,
                "Labels": {"org.opencontainers.image.revision": "ignored"},
            },
            "RootFS": {"Type": "layers", "Layers": layers or ["sha256:" + "a" * 64]},
        }
    ]


def test_canonical_runtime_identity_is_stable_for_identical_inputs(tmp_path: Path) -> None:
    first = tmp_path / "first.tar"
    second = tmp_path / "second.tar"
    _write_rootfs_tar(first)
    _write_rootfs_tar(second)

    first_identity = canonical_runtime_identity(
        image_role="gateway",
        base_image=GATEWAY_BASE_IMAGE,
        rootfs_digest=canonical_rootfs_digest(first),
        runtime_config=canonical_runtime_config(_inspect_config()),
    )
    second_identity = canonical_runtime_identity(
        image_role="gateway",
        base_image=GATEWAY_BASE_IMAGE,
        rootfs_digest=canonical_rootfs_digest(second),
        runtime_config=canonical_runtime_config(_inspect_config()),
    )

    assert first_identity["identity"] == second_identity["identity"]


@pytest.mark.parametrize(
    "change",
    ["content", "mode", "owner", "base", "user", "entrypoint", "env"],
)
def test_canonical_runtime_identity_changes_for_security_relevant_inputs(
    tmp_path: Path, change: str
) -> None:
    baseline = tmp_path / "baseline.tar"
    changed = tmp_path / "changed.tar"
    _write_rootfs_tar(baseline)
    _write_rootfs_tar(
        changed,
        content=b"changed" if change == "content" else b"hello",
        mode=0o755 if change == "mode" else 0o555,
        uid=1001 if change == "owner" else 1000,
    )
    base_image = (
        "gcr.io/distroless/python3-debian13:nonroot@sha256:" + "9" * 64
        if change == "base"
        else GATEWAY_BASE_IMAGE
    )
    config = _inspect_config(
        user="1001:1001" if change == "user" else "1000:1000",
        entrypoint=["/other"] if change == "entrypoint" else None,
        env=["PATH=/usr/bin", "EXTRA=1"] if change == "env" else None,
    )
    baseline_identity = canonical_runtime_identity(
        image_role="gateway",
        base_image=GATEWAY_BASE_IMAGE,
        rootfs_digest=canonical_rootfs_digest(baseline),
        runtime_config=canonical_runtime_config(_inspect_config()),
    )
    changed_identity = canonical_runtime_identity(
        image_role="gateway",
        base_image=base_image,
        rootfs_digest=canonical_rootfs_digest(changed),
        runtime_config=canonical_runtime_config(config),
    )

    assert changed_identity["identity"] != baseline_identity["identity"]


def test_canonical_runtime_identity_ignores_layer_serialization_when_rootfs_matches(
    tmp_path: Path,
) -> None:
    rootfs = tmp_path / "rootfs.tar"
    _write_rootfs_tar(rootfs)
    first = canonical_runtime_identity(
        image_role="agent",
        base_image=AGENT_BASE_IMAGE,
        rootfs_digest=canonical_rootfs_digest(rootfs),
        runtime_config=canonical_runtime_config(_inspect_config()),
    )
    second = canonical_runtime_identity(
        image_role="agent",
        base_image=AGENT_BASE_IMAGE,
        rootfs_digest=canonical_rootfs_digest(rootfs),
        runtime_config=canonical_runtime_config(
            _inspect_config(layers=["sha256:" + "b" * 64, "sha256:" + "c" * 64])
        ),
    )

    assert first["identity"] == second["identity"]


@pytest.mark.parametrize("volumes", [None, {}, {"Volumes": None}])
def test_canonical_runtime_config_normalizes_no_declared_volumes(volumes) -> None:
    inspect_data = _inspect_config(volumes={})
    if volumes is None:
        inspect_data[0]["Config"].pop("Volumes")
    elif "Volumes" in volumes:
        inspect_data[0]["Config"]["Volumes"] = volumes["Volumes"]

    assert canonical_runtime_config(inspect_data)["volumes"] == []


def test_canonical_runtime_config_sorts_volume_paths_and_ignores_options() -> None:
    first = canonical_runtime_config(
        _inspect_config(volumes={"/cache": {"ignored": "a"}, "/workspace": {}})
    )
    second = canonical_runtime_config(
        _inspect_config(volumes={"/workspace": {}, "/cache": {"ignored": "b"}})
    )

    assert first["volumes"] == ["/cache", "/workspace"]
    assert first == second


def _runtime_identity_for_volumes(tmp_path: Path, volumes) -> str:
    rootfs = tmp_path / "rootfs.tar"
    _write_rootfs_tar(rootfs)
    return canonical_runtime_identity(
        image_role="gateway",
        base_image=GATEWAY_BASE_IMAGE,
        rootfs_digest=canonical_rootfs_digest(rootfs),
        runtime_config=canonical_runtime_config(_inspect_config(volumes=volumes)),
    )["identity"]


def test_canonical_runtime_identity_changes_when_volume_is_added(tmp_path: Path) -> None:
    assert _runtime_identity_for_volumes(
        tmp_path, {"/cache": {}}
    ) != _runtime_identity_for_volumes(tmp_path, {})


def test_canonical_runtime_identity_changes_when_volume_is_removed(tmp_path: Path) -> None:
    assert _runtime_identity_for_volumes(
        tmp_path, {"/cache": {}, "/workspace": {}}
    ) != _runtime_identity_for_volumes(tmp_path, {"/cache": {}})


def test_canonical_runtime_identity_changes_when_volume_is_renamed(tmp_path: Path) -> None:
    assert _runtime_identity_for_volumes(
        tmp_path, {"/cache": {}}
    ) != _runtime_identity_for_volumes(tmp_path, {"/workspace": {}})


@pytest.mark.parametrize(
    ("volumes", "message"),
    [
        (["/cache"], "Config.Volumes must be an object"),
        ({"/cache": []}, "Config.Volumes options must be an object"),
        ({"cache": {}}, "absolute normalized"),
        ({"/cache/../workspace": {}}, "absolute normalized"),
        ({"/cache/": {}}, "absolute normalized"),
        ({"/bad\npath": {}}, "absolute normalized"),
    ],
)
def test_canonical_runtime_config_rejects_malformed_volumes(volumes, message) -> None:
    with pytest.raises(RuntimeImageError, match=message):
        canonical_runtime_config(_inspect_config(volumes=volumes))


def test_canonical_runtime_identity_rejects_missing_or_wrong_evidence(tmp_path: Path) -> None:
    empty = tmp_path / "empty.tar"
    with tarfile.open(empty, "w"):
        pass
    with pytest.raises(RuntimeImageError, match="must not be empty"):
        canonical_rootfs_digest(empty)
    with pytest.raises(RuntimeImageError, match="exactly one image"):
        canonical_runtime_config([])
    with pytest.raises(RuntimeImageError, match="image role"):
        canonical_runtime_identity(
            image_role="other",
            base_image=GATEWAY_BASE_IMAGE,
            rootfs_digest="sha256:" + "1" * 64,
            runtime_config=canonical_runtime_config(_inspect_config()),
        )
    with pytest.raises(RuntimeImageError, match="pinned by digest"):
        canonical_runtime_identity(
            image_role="gateway",
            base_image="python:latest",
            rootfs_digest="sha256:" + "1" * 64,
            runtime_config=canonical_runtime_config(_inspect_config()),
        )


def test_trivy_summary_tracks_fixable_and_unfixed_high_critical(tmp_path: Path) -> None:
    scan = tmp_path / "agent.trivy.json"
    scan.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Target": "agent",
                        "Type": "debian",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-fixed",
                                "PkgName": "libssl3",
                                "InstalledVersion": "1",
                                "Severity": "HIGH",
                                "FixedVersion": "2",
                            },
                            {
                                "VulnerabilityID": "CVE-unfixed",
                                "PkgName": "zlib1g",
                                "InstalledVersion": "1",
                                "Severity": "CRITICAL",
                            },
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    summary = summarize_trivy_high_critical([scan])

    assert summary["status"] == "hosted_trivy_high_critical_policy_failed"
    assert summary["severity_counts"] == {"CRITICAL": 1, "HIGH": 1}
    assert summary["fixability_counts"]["fixed"] == {"CRITICAL": 0, "HIGH": 1}
    assert summary["fixability_counts"]["unfixed"] == {"CRITICAL": 1, "HIGH": 0}
    assert summary["findings"][0]["fix_available"] is True


def test_trivy_summary_accepts_zero_finding_results(tmp_path: Path) -> None:
    scan = tmp_path / "agent.trivy.json"
    scan.write_text(
        json.dumps({"Results": [{"Target": "agent", "Type": "debian"}]}),
        encoding="utf-8",
    )

    summary = summarize_trivy_high_critical([scan])

    assert summary["status"] == "hosted_trivy_high_critical_policy_passed"
    assert summary["severity_counts"] == {"CRITICAL": 0, "HIGH": 0}
    assert summary["findings"] == []


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"Results": ["not-object"]}, "result must be an object"),
        (
            {"Results": [{"Target": "gateway", "Vulnerabilities": "not-list"}]},
            "vulnerabilities must be a list",
        ),
        (
            {"Results": [{"Target": "gateway", "Vulnerabilities": ["not-object"]}]},
            "vulnerability must be an object",
        ),
    ],
)
def test_trivy_summary_rejects_malformed_result_shapes(
    tmp_path: Path, payload, message
) -> None:
    scan = tmp_path / "gateway.trivy.json"
    scan.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(RuntimeImageError, match=message):
        summarize_trivy_high_critical([scan])


def test_trivy_summary_ignores_non_high_critical_findings(tmp_path: Path) -> None:
    scan = tmp_path / "gateway.trivy.json"
    _write_scan(
        scan,
        "gateway",
        [_finding("CVE-low", "libsafe", "1", severity="LOW")],
    )

    summary = summarize_trivy_high_critical([scan])

    assert summary["status"] == "hosted_trivy_high_critical_policy_passed"
    assert summary["findings"] == []



def _finding(cve: str, package: str, installed: str, *, severity: str = "HIGH", fixed: str = "") -> dict[str, str]:
    item = {
        "VulnerabilityID": cve,
        "PkgName": package,
        "InstalledVersion": installed,
        "Severity": severity,
    }
    if fixed:
        item["FixedVersion"] = fixed
    return item


def _write_scan(path: Path, target: str, findings: list[dict[str, str]]) -> None:
    result = {"Target": target, "Type": "debian"}
    if findings:
        result["Vulnerabilities"] = findings
    path.write_text(json.dumps({"Results": [result]}), encoding="utf-8")


def _exception_manifest(tmp_path: Path, *, mutate=None) -> Path:
    source = json.loads((ROOT / "runtime-images/vulnerability-exceptions.json").read_text(encoding="utf-8"))
    data = copy.deepcopy(source)
    if mutate is not None:
        mutate(data)
    path = tmp_path / "vulnerability-exceptions.json"
    path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
    return path


def _reviewed_gateway_findings() -> list[dict[str, str]]:
    manifest = json.loads((ROOT / "runtime-images/vulnerability-exceptions.json").read_text(encoding="utf-8"))
    findings = []
    for exception in manifest["exceptions"]:
        for package in exception["affected_packages"]:
            findings.append(
                _finding(
                    exception["cve"],
                    package["name"],
                    package["installed_version"],
                )
            )
    return findings


def _evaluate_policy(tmp_path: Path, gateway_findings: list[dict[str, str]], *, manifest_mutate=None, agent_findings=None, gateway_digest=GATEWAY_REVIEWED_IMAGE_DIGEST):
    gateway = tmp_path / "gateway.trivy.json"
    agent = tmp_path / "agent.trivy.json"
    _write_scan(gateway, "gateway", gateway_findings)
    _write_scan(agent, "agent", agent_findings or [])
    return evaluate_trivy_high_critical_policy(
        [gateway, agent],
        exception_manifest=_exception_manifest(tmp_path, mutate=manifest_mutate),
        gateway_image_digest=gateway_digest,
        agent_image_digest=AGENT_REVIEWED_IMAGE_DIGEST,
        as_of=date(2026, 10, 7),
    )


def test_reviewed_exception_set_passes_exact_digest_policy(tmp_path: Path) -> None:
    policy = _evaluate_policy(tmp_path, _reviewed_gateway_findings())

    assert policy["status"] == "hosted_trivy_high_critical_policy_passed"
    assert policy["severity_counts"] == {"CRITICAL": 0, "HIGH": 26}
    assert policy["fixability_counts"]["fixed"] == {"CRITICAL": 0, "HIGH": 0}
    assert policy["exception_count"] == 13
    assert policy["accepted_exception_count"] == 26
    assert policy["rejected_findings"] == []


@pytest.mark.parametrize(
    ("finding", "reason"),
    [
        (_finding("CVE-2099-0001", "libnew", "1"), "unmatched gateway high vulnerability"),
        (_finding("CVE-2025-69720", "libncursesw6", "6.5+20250216-2", severity="CRITICAL"), "critical vulnerabilities are forbidden"),
        (_finding("CVE-2025-69720", "libncursesw6", "6.5+20250216-2", fixed="6.6"), "fixable high vulnerabilities require remediation"),
        (_finding("CVE-2025-69720", "libncursesw6", "wrong"), "unmatched gateway high vulnerability"),
        (_finding("CVE-2025-69720", "wrong", "6.5+20250216-2"), "unmatched gateway high vulnerability"),
    ],
)
def test_exception_policy_rejects_unmatched_critical_or_fixable_findings(tmp_path: Path, finding, reason) -> None:
    policy = _evaluate_policy(tmp_path, _reviewed_gateway_findings() + [finding])

    assert policy["status"] == "hosted_trivy_high_critical_policy_failed"
    assert any(item["reason"] == reason for item in policy["rejected_findings"])


def test_exception_policy_rejects_wrong_gateway_digest(tmp_path: Path) -> None:
    with pytest.raises(RuntimeImageError, match="gateway image digest does not match"):
        _evaluate_policy(tmp_path, _reviewed_gateway_findings(), gateway_digest="sha256:" + "9" * 64)


def test_exception_policy_rejects_wrong_base_digest(tmp_path: Path) -> None:
    with pytest.raises(RuntimeImageError, match="gateway base image does not match"):
        _evaluate_policy(
            tmp_path,
            _reviewed_gateway_findings(),
            manifest_mutate=lambda data: data.__setitem__("gateway_base_image", "gcr.io/distroless/python3-debian13:nonroot@sha256:" + "9" * 64),
        )


def test_exception_policy_rejects_expired_exception(tmp_path: Path) -> None:
    with pytest.raises(RuntimeImageError, match="exception expired"):
        load_vulnerability_exceptions(
            _exception_manifest(tmp_path),
            gateway_image_digest=GATEWAY_REVIEWED_IMAGE_DIGEST,
            as_of=date(2026, 11, 7),
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda data: data["exceptions"][0].pop("owner"), "owner mismatch"),
        (lambda data: data["exceptions"][0].__setitem__("evidence", ""), "evidence is required"),
        (lambda data: data["exceptions"][0].__setitem__("advisory_references", []), "advisory references are required"),
        (lambda data: data["exceptions"][0].__setitem__("cve", "CVE-*"), "exact CVE"),
        (lambda data: data["exceptions"][0].__setitem__("image_role", "agent"), "gateway image"),
    ],
)
def test_exception_manifest_rejects_malformed_wildcard_or_agent_exceptions(tmp_path: Path, mutate, message) -> None:
    with pytest.raises(RuntimeImageError, match=message):
        load_vulnerability_exceptions(
            _exception_manifest(tmp_path, mutate=mutate),
            gateway_image_digest=GATEWAY_REVIEWED_IMAGE_DIGEST,
            as_of=date(2026, 10, 7),
        )


def test_exception_policy_rejects_agent_high_even_if_cve_is_listed(tmp_path: Path) -> None:
    policy = _evaluate_policy(
        tmp_path,
        _reviewed_gateway_findings(),
        agent_findings=[_finding("CVE-2025-69720", "libncursesw6", "6.5+20250216-2")],
    )

    assert policy["status"] == "hosted_trivy_high_critical_policy_failed"
    assert any(item["reason"] == "agent exceptions are forbidden" for item in policy["rejected_findings"])


def test_exception_policy_rejects_unknown_image_role(tmp_path: Path) -> None:
    gateway = tmp_path / "other.trivy.json"
    agent = tmp_path / "agent.trivy.json"
    _write_scan(gateway, "other", [_finding("CVE-2099-0001", "libnew", "1")])
    _write_scan(agent, "agent", [])

    policy = evaluate_trivy_high_critical_policy(
        [gateway, agent],
        exception_manifest=_exception_manifest(tmp_path),
        gateway_image_digest=GATEWAY_REVIEWED_IMAGE_DIGEST,
        agent_image_digest=AGENT_REVIEWED_IMAGE_DIGEST,
        as_of=date(2026, 10, 7),
    )

    assert policy["status"] == "hosted_trivy_high_critical_policy_failed"
    assert any(item["reason"] == "unknown image role" for item in policy["rejected_findings"])


def test_exception_policy_rejects_stale_exception_entries(tmp_path: Path) -> None:
    findings = _reviewed_gateway_findings()[1:]
    policy = _evaluate_policy(tmp_path, findings)

    assert policy["status"] == "hosted_trivy_high_critical_policy_failed"
    assert any(item["reason"] == "stale exception does not match a current scan finding" for item in policy["rejected_findings"])


def test_exception_policy_rejects_missing_or_malformed_scan_evidence(tmp_path: Path) -> None:
    manifest = _exception_manifest(tmp_path)
    malformed = tmp_path / "gateway.trivy.json"
    malformed.write_text("{", encoding="utf-8")
    agent = tmp_path / "agent.trivy.json"
    _write_scan(agent, "agent", [])

    with pytest.raises(RuntimeImageError, match="invalid Trivy JSON"):
        evaluate_trivy_high_critical_policy(
            [malformed, agent],
            exception_manifest=manifest,
            gateway_image_digest=GATEWAY_REVIEWED_IMAGE_DIGEST,
            agent_image_digest=AGENT_REVIEWED_IMAGE_DIGEST,
            as_of=date(2026, 10, 7),
        )


def test_exception_policy_rejects_artifact_image_identity_mismatch(tmp_path: Path) -> None:
    def mutate(data):
        data["gateway_image_digest"] = "sha256:" + "8" * 64
        for exception in data["exceptions"]:
            exception["gateway_image_digest"] = data["gateway_image_digest"]

    with pytest.raises(RuntimeImageError, match="gateway image digest does not match"):
        _evaluate_policy(tmp_path, _reviewed_gateway_findings(), manifest_mutate=mutate)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda data: data.__setitem__("schema", "wrong"), "invalid vulnerability"),
        (lambda data: data.__setitem__("schema_version", 2), "unsupported"),
        (lambda data: data.__setitem__("exceptions", []), "exceptions are required"),
        (lambda data: data.__setitem__("agent_image_digest", GATEWAY_REVIEWED_IMAGE_DIGEST), "ambiguous"),
        (lambda data: data["exceptions"].__setitem__(0, "not-object"), "must be an object"),
        (lambda data: data["exceptions"][0].__setitem__("cve", data["exceptions"][1]["cve"]), "duplicate"),
        (lambda data: data["exceptions"][0].__setitem__("severity", "CRITICAL"), "severity must be HIGH"),
        (lambda data: data["exceptions"][0].__setitem__("approval_date", "2099-01-01"), "future"),
        (lambda data: data["exceptions"][0].__setitem__("approval_date", "bad"), "YYYY-MM-DD"),
        (lambda data: data["exceptions"][0].__setitem__("reachability", "probably"), "classification"),
        (lambda data: data["exceptions"][0].__setitem__("advisory_references", ["http://example.test"]), "HTTPS"),
        (lambda data: data["exceptions"][0].__setitem__("reevaluation_triggers", []), "triggers"),
        (lambda data: data["exceptions"][0].__setitem__("affected_packages", []), "affected packages"),
        (lambda data: data["exceptions"][0]["affected_packages"].__setitem__(0, "not-object"), "package must be"),
        (
            lambda data: data["exceptions"][0]["affected_packages"][0].__setitem__("name", "lib*"),
            "must be exact",
        ),
    ],
)
def test_exception_manifest_rejects_additional_malformed_shapes(
    tmp_path: Path, mutate, message
) -> None:
    with pytest.raises(RuntimeImageError, match=message):
        load_vulnerability_exceptions(
            _exception_manifest(tmp_path, mutate=mutate),
            gateway_image_digest=GATEWAY_REVIEWED_IMAGE_DIGEST,
            as_of=date(2026, 10, 7),
        )
