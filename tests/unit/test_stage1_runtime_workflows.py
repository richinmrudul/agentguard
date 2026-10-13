import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
FULL_SHA_EXPR = "${{ github.sha }}"


def _workflow(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _triggers(workflow: dict) -> dict:
    # PyYAML 1.1 treats the unquoted YAML key "on" as boolean true.
    triggers = workflow.get("on", workflow.get(True))
    assert isinstance(triggers, dict)
    return triggers


def _step(job: dict, name: str) -> dict:
    for step in job["steps"]:
        if step.get("name") == name:
            return step
    raise AssertionError(f"missing step: {name}")


def _uses(job: dict) -> list[str]:
    return [step["uses"] for step in job["steps"] if "uses" in step]


def test_pr_runtime_image_workflow_builds_without_push_or_secrets() -> None:
    workflow_path = ROOT / ".github/workflows/stage1-runtime-images.yml"
    workflow = _workflow(workflow_path)

    assert "pull_request" in workflow[True]
    assert workflow["permissions"] == {"contents": "read"}
    text = workflow_path.read_text(encoding="utf-8")
    assert "push: true" not in text
    assert "docker push" not in text
    assert "CODEX_API_KEY" not in text
    assert "packages: write" not in text
    assert "workflow_dispatch:" not in text
    assert "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd" in text
    assert "anchore/syft@sha256:cefadcf11bd9cce9e3ec5248bb1538a84e33d519486c1b4523ac155c9b5f5033" in text
    assert "aquasec/trivy@sha256:adbf5948d99de471725d37d2cfbd982178971d1cf081615284671d1c8ba99fb8" in text
    assert "--severity HIGH,CRITICAL --exit-code 0 --skip-version-check" in text
    assert "Enforce vulnerability policy" in text
    assert "evaluate_trivy_high_critical_policy" in text
    assert "runtime-images/vulnerability-exceptions.json" in text
    assert "runtime_image_identity.py" in text
    assert "dist-runtime-image-canonical-identities.txt" in text
    assert "canonical runtime identity mismatch" in text
    assert "Compare repeat-build SBOM and vulnerability evidence" in text
    assert "repeat-build-comparison.json" in text
    assert "repeat-build Trivy finding mismatch" in text
    assert 'target.replace(f"{image}-image-a.tar"' in text
    assert "exception_count" in text
    assert "expected exactly 15 reviewed vulnerability exception records" in text
    assert "trivy-version.txt" in text
    assert "trivy-db-metadata.json" in text
    assert "validate_scanner_metadata" in text
    assert "bash scripts/stage1_runtime_images.sh" in text
    assert "if: always()" in text


def test_publication_workflow_is_manual_activation_gated_and_main_only() -> None:
    workflow_path = ROOT / ".github/workflows/stage1-runtime-images-publish.yml"
    workflow = _workflow(workflow_path)
    triggers = _triggers(workflow)
    jobs = workflow["jobs"]
    text = workflow_path.read_text(encoding="utf-8")

    assert set(triggers) == {"workflow_dispatch"}
    assert set(triggers["workflow_dispatch"]["inputs"]) == {
        "required_source_commit",
        "approval_phrase",
    }
    assert "pull_request:" not in text
    assert "\npush:" not in text
    assert "APPROVE_STAGE1_RUNTIME_IMAGE_PUBLICATION" in text
    assert "github.ref == 'refs/heads/main'" in jobs["prepare"]["if"]
    assert "github.ref == 'refs/heads/main'" in jobs["publish"]["if"]
    assert "github.event.inputs.required_source_commit == github.sha" in text
    assert "vars.STAGE1_RUNTIME_PUBLICATION_ENABLED == 'true'" in jobs["publish"]["if"]
    assert 'test "$PUBLICATION_ENABLED" = "true"' in text


def test_publication_permissions_and_environment_are_narrow() -> None:
    workflow = _workflow(ROOT / ".github/workflows/stage1-runtime-images-publish.yml")
    prepare = workflow["jobs"]["prepare"]
    publish = workflow["jobs"]["publish"]

    assert workflow["permissions"] == {"contents": "read"}
    assert prepare["permissions"] == {"contents": "read"}
    assert "packages" not in prepare["permissions"]
    assert publish["permissions"] == {
        "contents": "read",
        "packages": "write",
        "id-token": "write",
        "attestations": "write",
    }
    assert publish["environment"]["name"] == "stage1-runtime-images"
    assert publish["needs"] == "prepare"


def test_publication_builds_once_then_publishes_downloaded_artifacts() -> None:
    workflow_path = ROOT / ".github/workflows/stage1-runtime-images-publish.yml"
    workflow = _workflow(workflow_path)
    prepare = workflow["jobs"]["prepare"]
    publish = workflow["jobs"]["publish"]
    text = workflow_path.read_text(encoding="utf-8")
    prepare_text = yaml.safe_dump(prepare, sort_keys=False)
    publish_text = yaml.safe_dump(publish, sort_keys=False)

    assert prepare_text.count("docker build") == 2
    assert "docker build \\" not in publish_text
    assert "docker build --" not in publish_text
    assert "docker save \"$GATEWAY_IMAGE\"" in text
    assert "docker save \"$AGENT_IMAGE\"" in text
    assert "image-archives.SHA256SUMS" in text
    assert "stage1_publication_manifest.py verify-archives" in text
    assert publish["steps"][1]["uses"].startswith("actions/download-artifact@")
    assert "docker load --input validated-publication/gateway-image.tar" in publish_text
    assert "docker load --input validated-publication/agent-image.tar" in publish_text
    assert "docker push \"$GATEWAY_IMAGE\"" in publish_text
    assert "docker push \"$AGENT_IMAGE\"" in publish_text
    assert text.count("stage1-runtime-images-publication-${{ github.sha }}") == 2


def test_publication_uses_only_full_commit_tags_and_two_coordinates() -> None:
    workflow_path = ROOT / ".github/workflows/stage1-runtime-images-publish.yml"
    workflow = _workflow(workflow_path)
    text = workflow_path.read_text(encoding="utf-8")

    assert workflow["env"]["GATEWAY_IMAGE"] == (
        "ghcr.io/richinmrudul/agentguard/stage1-gateway:" + FULL_SHA_EXPR
    )
    assert workflow["env"]["AGENT_IMAGE"] == (
        "ghcr.io/richinmrudul/agentguard/stage1-codex-agent:" + FULL_SHA_EXPR
    )
    assert ":latest" not in text
    assert "release-channel" not in text
    assert ":${{ github.sha }}" in text
    assert re.search(r"stage1-gateway:\$\{\{ github\.sha \}\}", text)
    assert re.search(r"stage1-codex-agent:\$\{\{ github\.sha \}\}", text)
    coordinates = set(re.findall(r"ghcr\.io/richinmrudul/agentguard/stage1-[a-z-]+", text))
    assert coordinates == {
        "ghcr.io/richinmrudul/agentguard/stage1-gateway",
        "ghcr.io/richinmrudul/agentguard/stage1-codex-agent",
    }


def test_publication_is_linux_amd64_only_and_checks_reviewed_identities() -> None:
    text = (ROOT / ".github/workflows/stage1-runtime-images-publish.yml").read_text(
        encoding="utf-8"
    )

    assert "TARGET_PLATFORM: linux/amd64" in text
    assert "--platform \"$TARGET_PLATFORM\"" in text
    assert "linux/arm64" not in text
    assert "GATEWAY_REVIEWED_IDENTITY" in text
    assert "AGENT_REVIEWED_IDENTITY" in text
    assert "sha256:b30a59331f1b111b6620203d2e25ab8c1cd20a046559ee98d1018d0a5157ac4a" in text
    assert "sha256:ef4131b5ee0ffc6da4152d9ba91dd3c468dd46732a3fca2f0d2f4c4be0a57338" in text
    assert "scripts/runtime_image_identity.py" in text
    assert "stage1_publication_manifest.py prepare" in text
    assert "stage1_publication_manifest.py post-publish" in text


def test_publication_attests_and_verifies_published_digests() -> None:
    workflow = _workflow(ROOT / ".github/workflows/stage1-runtime-images-publish.yml")
    publish = workflow["jobs"]["publish"]
    publish_text = yaml.safe_dump(publish, sort_keys=False)
    uses = _uses(publish)

    assert any(
        action.startswith(
            "actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a"
        )
        for action in uses
    )
    assert "subject-digest: ${{ steps.digests.outputs.gateway_digest }}" in publish_text
    assert "subject-digest: ${{ steps.digests.outputs.agent_digest }}" in publish_text
    workflow_text = (ROOT / ".github/workflows/stage1-runtime-images-publish.yml").read_text(
        encoding="utf-8"
    )
    assert "docker buildx imagetools inspect \"$GATEWAY_IMAGE\"" in workflow_text
    assert "docker buildx imagetools inspect \"$AGENT_IMAGE\"" in workflow_text
    assert "docker pull \"$gateway_ref\"" in workflow_text
    assert "docker pull \"$agent_ref\"" in workflow_text
    assert "Rejected published $image digest: $ref" in workflow_text
    assert "Reject previously failed publication digests" in publish_text
    assert "mock-egress-pulled-digest.json" in publish_text


def test_publication_compares_post_pull_sbom_rows_and_full_mock_egress() -> None:
    workflow_text = (ROOT / ".github/workflows/stage1-runtime-images-publish.yml").read_text(
        encoding="utf-8"
    )

    assert "sbom_rows_digest" in (
        ROOT / "scripts/stage1_publication_manifest.py"
    ).read_text(encoding="utf-8")
    assert "post-publication SBOM package rows mismatch" in (
        ROOT / "scripts/stage1_publication_manifest.py"
    ).read_text(encoding="utf-8")
    assert "scripts/stage1_pulled_digest_integration.py" in workflow_text
    assert "--gateway-ref \"$gateway_ref\"" in workflow_text
    assert "--agent-ref \"$agent_ref\"" in workflow_text
    assert "public_provider_contact" in (
        ROOT / "scripts/stage1_pulled_digest_integration.py"
    ).read_text(encoding="utf-8")
    assert "credential_canary_not_retained" in (
        ROOT / "scripts/stage1_pulled_digest_integration.py"
    ).read_text(encoding="utf-8")
    assert "disallowed_destination_denied" in (
        ROOT / "scripts/stage1_pulled_digest_integration.py"
    ).read_text(encoding="utf-8")
    assert "direct_bypass_denied" in (
        ROOT / "scripts/stage1_pulled_digest_integration.py"
    ).read_text(encoding="utf-8")
    assert "gateway_crash_detected" in (
        ROOT / "scripts/stage1_pulled_digest_integration.py"
    ).read_text(encoding="utf-8")
    assert "cleanup_and_liveness" in (
        ROOT / "scripts/stage1_pulled_digest_integration.py"
    ).read_text(encoding="utf-8")
    assert '"public_provider_contact": False' in (
        ROOT / "scripts/stage1_pulled_digest_integration.py"
    ).read_text(encoding="utf-8")


def test_publication_artifact_verification_precedes_login_and_push() -> None:
    workflow = _workflow(ROOT / ".github/workflows/stage1-runtime-images-publish.yml")
    steps = [step["name"] for step in workflow["jobs"]["publish"]["steps"]]

    assert steps.index("Download exact validated publication artifacts") < steps.index(
        "Verify downloaded artifacts before registry authentication"
    )
    assert steps.index("Verify downloaded artifacts before registry authentication") < steps.index(
        "Log in to GHCR with GitHub token"
    )
    assert steps.index("Verify downloaded artifacts before registry authentication") < steps.index(
        "Load exact validated image archives"
    )
    assert steps.index("Log in to GHCR with GitHub token") < steps.index(
        "Publish exact validated OCI subjects"
    )
    assert steps.index("Enforce post-publication evidence policy") < steps.index(
        "Run full local mock egress integration using pulled digest references"
    )
    assert steps.index("Run full local mock egress integration using pulled digest references") < steps.index(
        "Attest approved published gateway digest"
    )
    assert steps.index("Run full local mock egress integration using pulled digest references") < steps.index(
        "Attest approved published Codex agent digest"
    )
    assert steps.index("Reject previously failed publication digests") < steps.index(
        "Pull by digest and verify canonical identities"
    )


def test_publication_binds_pulled_scans_before_policy_and_retains_failure_evidence() -> None:
    workflow = _workflow(ROOT / ".github/workflows/stage1-runtime-images-publish.yml")
    publish = workflow["jobs"]["publish"]
    publish_text = yaml.safe_dump(publish, sort_keys=False)
    steps = [step["name"] for step in publish["steps"]]

    assert "write-scan-bindings" in publish_text
    assert "scan-bindings.json" in publish_text
    assert steps.index("Regenerate SBOMs and rescan pulled-by-digest images") < steps.index(
        "Enforce post-publication evidence policy"
    )
    upload = _step(publish, "Upload post-publication evidence")
    assert upload["if"] == "always()"
    assert "validated-publication/post-publish/*.json" in yaml.safe_dump(upload)
