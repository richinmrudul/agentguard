from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def test_pr_runtime_image_workflow_builds_without_push_or_secrets() -> None:
    workflow_path = ROOT / ".github/workflows/stage1-runtime-images.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))

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
    assert "exception_count" in text
    assert "bash scripts/stage1_runtime_images.sh" in text
    assert "if: always()" in text


def test_publication_workflow_is_manual_commit_confirmed_and_least_scoped() -> None:
    workflow_path = ROOT / ".github/workflows/stage1-runtime-images-publish.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    text = workflow_path.read_text(encoding="utf-8")

    assert list(workflow[True]) == ["workflow_dispatch"]
    assert "pull_request:" not in text
    assert "push:" not in text
    assert "required_source_commit" in text
    assert "github.ref == 'refs/heads/main'" in text
    assert "packages: write" in text
    assert "attestations: write" not in text
    assert "id-token: write" not in text
    assert "ghcr.io/richinmrudul/agentguard" in text
    assert "${{ github.event.inputs.required_source_commit }}" in text
