"""Offline integrity checks for the frozen Codex model-compatibility candidate."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path


ROOT = Path(__file__).parents[2]
PATCH = ROOT / "runtime-images/codex-agent/model-gpt-5.2-2025-12-11.patch"
EXPECTED_PATCH = "f0cfb22492f69e71b6124c45afe5809ba1dcd0f9f63c3ac2bdce990987be44eb"
SNAPSHOT = "gpt-5.2-2025-12-11"


def test_reviewed_patch_is_exact_and_fail_closed() -> None:
    patch = PATCH.read_bytes()
    assert hashlib.sha256(patch).hexdigest() == EXPECTED_PATCH
    assert patch.count(b'"slug": "gpt-5.2-2025-12-11"') == 1
    assert b'"gpt-5.2-2025-12-11-unreviewed"' in patch
    assert b'"reviewed snapshot metadata is missing"' in patch
    assert b"used_fallback_model_metadata" in patch
    assert b'"apply_patch_tool_type": "freeform"' in patch
    assert b'"supports_reasoning_summary_parameter": false' in patch
    assert b'"use_responses_lite": false' in patch
    assert b'"input_modalities": ["text"]' in patch


def test_build_is_pinned_and_local_candidate_cannot_publish() -> None:
    script = (ROOT / "scripts/verify_reviewed_codex_model.sh").read_text()
    assert EXPECTED_PATCH in script
    assert "ff6aec96948b70d94983af2641a6b67c94faeff5" in script
    assert "406dfdd5c68f303a3a8d04f32b3965b3b0ca0361" in script
    assert "cargo build --locked --release" in script
    assert "docker push" not in script
    dockerfile = (
        ROOT / "runtime-images/codex-agent/Dockerfile.model-compatibility"
    ).read_text()
    assert "@sha256:31402671e20d26972f0345c4bf3263d4f5309c0f450cfbaece19b2b799caa93a" in dockerfile
    assert "COPY --chown=10001:10001 --chmod=0555 codex /opt/codex/bin/codex" in dockerfile
    assert "RUN " not in dockerfile


def test_mock_inspection_can_never_echo_unreviewed_values() -> None:
    source = ROOT / "runtime-images/stage1-metering/mock_responses_provider.py"
    spec = importlib.util.spec_from_file_location("stage1_mock_provider_inspection", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module._choice(SNAPSHOT, {SNAPSHOT}) == SNAPSHOT
    for value in ("FAKE_CREDENTIAL_CANARY", "Authorization: Bearer secret", "/private/path"):
        assert module._choice(value, {SNAPSHOT}) == "unexpected"
    assert module._choice([SNAPSHOT], {SNAPSHOT}) == "unexpected"
