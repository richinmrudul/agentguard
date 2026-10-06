import json
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
    RuntimeImageError,
    build_runtime_manifest,
    parse_codex_usage,
    runtime_image_context_digest,
    runtime_manifest_digest,
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
