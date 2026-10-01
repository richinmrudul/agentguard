#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentguard.evaluation.runtime_images import (  # noqa: E402
    AGENT_BASE_IMAGE,
    CODEX_INTEGRITY,
    CODEX_LINUX_X64_INTEGRITY,
    CODEX_VERSION,
    EXPECTED_CREDENTIAL_ENV,
    GATEWAY_BASE_IMAGE,
    RuntimeImageError,
    build_runtime_manifest,
    runtime_image_context_digest,
    runtime_manifest_digest,
    validate_runtime_manifest,
)


GATEWAY_CONTEXT = ROOT / "runtime-images/gateway"
AGENT_CONTEXT = ROOT / "runtime-images/codex-agent"
FLOATING_ACTION = re.compile(r"uses:\s*[^@\s]+@(v?\d+(?:\.\d+){0,2}|main|master)\b")
FLOATING_FROM = re.compile(r"^FROM\s+(?!.*@sha256:)", re.MULTILINE)
MUTABLE_NPM = re.compile(r'"@openai/codex"\s*:\s*"[^"]*[~^*<>]')
FORBIDDEN_RUNTIME = (
    "npm install",
    "npm update",
    "apt-get",
    "apk add",
    "curl ",
    "wget ",
    "docker.sock",
    "--privileged",
    "network: host",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--emit-manifest", type=Path)
    parser.add_argument("--source-commit", default="0" * 40)
    parser.add_argument("--gateway-digest", default="sha256:" + "1" * 64)
    parser.add_argument("--agent-digest", default="sha256:" + "2" * 64)
    args = parser.parse_args(argv)
    try:
        validate_policy()
        if args.emit_manifest:
            manifest = build_runtime_manifest(
                source_commit=args.source_commit,
                gateway_image_digest=args.gateway_digest,
                agent_image_digest=args.agent_digest,
                gateway_context_digest=runtime_image_context_digest(GATEWAY_CONTEXT),
                agent_context_digest=runtime_image_context_digest(AGENT_CONTEXT),
                sbom_digests={"gateway": "3" * 64, "agent": "4" * 64},
                provenance_digests={"gateway": "5" * 64, "agent": "6" * 64},
                scan_summaries={
                    "vulnerability_policy": {
                        "status": "not_run_phase1_mock_only",
                        "scanner_failures_suppressed": False,
                    },
                    "secret_scan": {"verified": True, "findings": 0},
                    "license": {"review_required": False},
                },
                usage_evidence_status="mock_supported",
            )
            validate_runtime_manifest(manifest)
            manifest["canonical_manifest_digest"] = runtime_manifest_digest(manifest)
            args.emit_manifest.write_text(
                json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
    except (AssertionError, RuntimeImageError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


def validate_policy() -> None:
    gateway_dockerfile = (GATEWAY_CONTEXT / "Dockerfile").read_text(encoding="utf-8")
    agent_dockerfile = (AGENT_CONTEXT / "Dockerfile").read_text(encoding="utf-8")
    lock = (AGENT_CONTEXT / "package-lock.json").read_text(encoding="utf-8")
    entrypoint = (AGENT_CONTEXT / "entrypoint.sh").read_text(encoding="utf-8")
    workflows = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / ".github/workflows").glob("*.yml"))
    )
    assert GATEWAY_BASE_IMAGE in gateway_dockerfile
    assert AGENT_BASE_IMAGE in agent_dockerfile
    assert FLOATING_FROM.search(gateway_dockerfile) is None
    assert FLOATING_FROM.search(agent_dockerfile) is None
    assert "USER 65532:65532" in gateway_dockerfile
    assert "USER 10001:10001" in agent_dockerfile
    assert "CODEX_API_KEY" in entrypoint
    assert EXPECTED_CREDENTIAL_ENV == "CODEX_API_KEY"
    assert f'"version": "{CODEX_VERSION}"' in lock
    assert CODEX_INTEGRITY in lock
    assert CODEX_LINUX_X64_INTEGRITY in lock
    assert MUTABLE_NPM.search((AGENT_CONTEXT / "package.json").read_text(encoding="utf-8")) is None
    for forbidden in FORBIDDEN_RUNTIME:
        runtime_text = gateway_dockerfile + "\n" + agent_dockerfile + "\n" + entrypoint
        assert forbidden not in runtime_text, f"forbidden runtime pattern present: {forbidden}"
    assert FLOATING_ACTION.search(workflows) is None
    publication = (ROOT / ".github/workflows/stage1-runtime-images-publish.yml").read_text(
        encoding="utf-8"
    )
    assert "workflow_dispatch:" in publication
    assert "pull_request:" not in publication
    assert "push:" not in publication
    assert "packages: write" in publication


if __name__ == "__main__":
    raise SystemExit(main())
