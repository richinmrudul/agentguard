"""Offline integrity checks for the frozen Codex model-compatibility candidate."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path


ROOT = Path(__file__).parents[2]
PATCH = ROOT / "runtime-images/codex-agent/model-gpt-5.2-2025-12-11.patch"
EXPECTED_PATCH = "00c4a5f5e690b1b09f440cfbaa3e98ed7799066009ad500ad399461c20b55a95"
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
    assert b'"base_instructions": "You are Codex, a coding assistant.' in patch


def test_build_is_pinned_and_local_candidate_cannot_publish() -> None:
    script = (ROOT / "scripts/verify_reviewed_codex_model.sh").read_text()
    assert EXPECTED_PATCH in script
    assert "ff6aec96948b70d94983af2641a6b67c94faeff5" in script
    assert "406dfdd5c68f303a3a8d04f32b3965b3b0ca0361" in script
    assert "cargo build --locked --target x86_64-unknown-linux-musl" in script
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
    assert module._tool_shape([{
        "type": "namespace", "name": "functions", "tools": [
            {"type": "function", "name": "exec_command"},
            {"type": "custom", "name": "apply_patch"},
        ],
    }]) == (["function", "custom"], ["exec_command", "apply_patch"])
    assert module._tool_shape([{"type": "function", "name": "wait_for_environment"}]) == (
        ["function"], ["unexpected"]
    )
    assert module._tool_shape([{"type": "function", "name": "request_plugin_install"}]) == (
        ["function"], ["unexpected"]
    )
    declaration = {
        "type": "function", "name": "exec_command",
        "description": "private prompt and path /private/fixture",
        "parameters": {"properties": {"secret": "FAKE_CREDENTIAL_CANARY"}},
    }
    diagnostic = module._tool_diagnostic([declaration])
    assert diagnostic == [{
        "index": 0, "type": "function", "name": "exec_command",
        "sha256": hashlib.sha256(json.dumps(
            declaration, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii")).hexdigest(),
    }]
    assert "private prompt" not in json.dumps(diagnostic)
    assert "FAKE_CREDENTIAL_CANARY" not in json.dumps(diagnostic)
    assert module._tool_diagnostic([{"type": "function", "name": "/private/path"}]) == []
    assert [record["name"] for record in module.REVIEWED_TOOL_DECLARATIONS] == [
        "exec_command", "write_stdin", "apply_patch",
    ]
    assert [record["type"] for record in module.REVIEWED_TOOL_DECLARATIONS] == [
        "function", "function", "custom",
    ]
    assert module._tool_shape([{
        "type": "namespace", "name": "functions", "tools": [
            {"type": "provider_hosted", "name": "private-value"},
        ],
    }]) == (["unexpected"], ["unexpected"])
    assert module._tool_shape([{
        "type": "namespace", "name": "functions", "tools": [
            {"type": "function", "name": "exec_command"} for _ in range(32)
        ],
    }, {"type": "custom", "name": "apply_patch"}]) == (
        ["unexpected"], ["unexpected"]
    )

    module.MODEL = SNAPSHOT
    payload = json.dumps({"model": SNAPSHOT, "stream": False}).encode()
    handler = object.__new__(module.MockHandler)
    handler.path = "/v1/responses/input_tokens"
    handler.headers = {"Content-Length": str(len(payload))}
    handler.rfile = io.BytesIO(payload)
    sent = []
    handler._send = lambda status, content_type, body: sent.append(
        (status, content_type, body)
    )
    handler.do_POST()
    assert sent[-1][0] == 200
    assert json.loads(sent[-1][2])["input_tokens"] == 7
    assert module.MockHandler.request_shapes[-1]["model"] == SNAPSHOT

    handler.path = "/inspection"
    handler.do_GET()
    inspection = json.loads(sent[-1][2])
    assert inspection["requests"][-1]["model"] == SNAPSHOT
    assert "Authorization" not in sent[-1][2].decode()

    handler.path = "/models"
    handler.do_GET()
    assert sent[-1][0] == 404

    handler.path = "/v1/responses"
    handler.headers = {
        "Content-Length": str(len(payload)),
        "Authorization": "Bearer FAKE_CREDENTIAL_CANARY",
    }
    handler.rfile = io.BytesIO(payload)
    handler.do_POST()
    assert sent[-1][0] == 400
    assert b"FAKE_CREDENTIAL_CANARY" not in sent[-1][2]


def test_reviewed_tool_contract_rejects_every_shape_mutation(monkeypatch) -> None:
    source = ROOT / "runtime-images/stage1-metering/mock_responses_provider.py"
    spec = importlib.util.spec_from_file_location("stage1_mock_tool_contract", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    tools = [
        {"type": "function", "name": "exec_command", "parameters": {"type": "object"}},
        {"type": "function", "name": "write_stdin", "parameters": {"type": "object"}},
        {"type": "custom", "name": "apply_patch", "format": {"type": "text"}},
    ]
    monkeypatch.setattr(module, "REVIEWED_TOOL_DECLARATIONS", module._tool_diagnostic(tools))
    assert module._reviewed_tool_contract(tools)
    variants = [
        [tools[1], tools[0], tools[2]],
        [tools[0], tools[0], tools[2]],
        tools[:2],
        tools + [{"type": "function", "name": "create_goal"}],
        [dict(tools[0], name="run_command"), *tools[1:]],
        [dict(tools[0], parameters={"type": "string"}), *tools[1:]],
        [dict(tools[0], type="custom"), *tools[1:]],
    ]
    for variant in variants:
        assert not module._reviewed_tool_contract(variant)
