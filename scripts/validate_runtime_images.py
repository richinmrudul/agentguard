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
    GATEWAY_REVIEWED_IMAGE_DIGEST,
    AGENT_REVIEWED_IMAGE_DIGEST,
    RuntimeImageError,
    build_runtime_manifest,
    runtime_image_context_digest,
    runtime_manifest_digest,
    evaluate_trivy_high_critical_policy,
    load_vulnerability_exceptions,
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
FORBIDDEN_FINAL_AGENT = (
    "/usr/local/bin/node",
    "/usr/local/bin/npm",
    "node_modules",
    "YARN_VERSION",
    "docker-entrypoint.sh",
)
FORBIDDEN_FINAL_GATEWAY = (
    "pip",
    "apt-get",
    "dpkg",
    "/bin/sh -c",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--emit-manifest", type=Path)
    parser.add_argument("--source-commit", default="0" * 40)
    parser.add_argument("--gateway-digest", default="sha256:" + "1" * 64)
    parser.add_argument("--agent-digest", default="sha256:" + "2" * 64)
    parser.add_argument("--trivy-json", type=Path, action="append", default=[])
    parser.add_argument("--exception-manifest", type=Path, default=ROOT / "runtime-images/vulnerability-exceptions.json")
    args = parser.parse_args(argv)
    try:
        validate_policy(args.trivy_json, exception_manifest=args.exception_manifest, gateway_digest=args.gateway_digest, agent_digest=args.agent_digest)
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


def validate_policy(
    trivy_json: list[Path] | None = None,
    *,
    exception_manifest: Path = ROOT / "runtime-images/vulnerability-exceptions.json",
    gateway_digest: str = GATEWAY_REVIEWED_IMAGE_DIGEST,
    agent_digest: str = AGENT_REVIEWED_IMAGE_DIGEST,
) -> None:
    gateway_dockerfile = (GATEWAY_CONTEXT / "Dockerfile").read_text(encoding="utf-8")
    agent_dockerfile = (AGENT_CONTEXT / "Dockerfile").read_text(encoding="utf-8")
    gateway_final = final_stage(gateway_dockerfile)
    agent_final = final_stage(agent_dockerfile)
    lock = (AGENT_CONTEXT / "package-lock.json").read_text(encoding="utf-8")
    entrypoint = (AGENT_CONTEXT / "entrypoint.c").read_text(encoding="utf-8")
    workflows = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / ".github/workflows").glob("*.yml"))
    )
    load_vulnerability_exceptions(
        exception_manifest,
        gateway_image_digest=GATEWAY_REVIEWED_IMAGE_DIGEST,
        as_of=__import__("datetime").date(2026, 10, 9),
    )
    assert GATEWAY_BASE_IMAGE in gateway_dockerfile
    assert AGENT_BASE_IMAGE in agent_dockerfile
    assert FLOATING_FROM.search(gateway_dockerfile) is None
    assert FLOATING_FROM.search(agent_dockerfile) is None
    assert "USER 65532:65532" in gateway_dockerfile
    assert "USER 10001:10001" in agent_dockerfile
    assert "CODEX_API_KEY" in entrypoint
    assert EXPECTED_CREDENTIAL_ENV == "CODEX_API_KEY"
    assert "execv(\"/opt/codex/bin/codex\"" in entrypoint
    assert f'"version": "{CODEX_VERSION}"' in lock
    assert CODEX_INTEGRITY in lock
    assert CODEX_LINUX_X64_INTEGRITY in lock
    assert MUTABLE_NPM.search((AGENT_CONTEXT / "package.json").read_text(encoding="utf-8")) is None
    for forbidden in FORBIDDEN_RUNTIME:
        runtime_text = gateway_final + "\n" + agent_final + "\n" + entrypoint
        assert forbidden not in runtime_text, f"forbidden runtime pattern present: {forbidden}"
    for forbidden in FORBIDDEN_FINAL_AGENT:
        assert forbidden not in agent_final, f"forbidden final agent content present: {forbidden}"
    for forbidden in FORBIDDEN_FINAL_GATEWAY:
        assert forbidden not in gateway_final, f"forbidden final gateway content present: {forbidden}"
    assert "COPY --from=codex-download /opt/codex-runtime /opt/codex" in agent_final
    assert "COPY --from=codex-download /opt/codex-build/node_modules" not in agent_dockerfile
    assert "codex-resources/voice" not in agent_dockerfile
    assert FLOATING_ACTION.search(workflows) is None
    publication = (ROOT / ".github/workflows/stage1-runtime-images-publish.yml").read_text(
        encoding="utf-8"
    )
    assert "workflow_dispatch:" in publication
    assert "pull_request:" not in publication
    assert "push:" not in publication
    assert "packages: write" in publication
    if trivy_json:
        summary = evaluate_trivy_high_critical_policy(
            trivy_json,
            exception_manifest=exception_manifest,
            gateway_image_digest=gateway_digest,
            agent_image_digest=agent_digest,
        )
        assert summary["status"] == "hosted_trivy_high_critical_policy_passed", (
            "high/critical vulnerability policy failed"
        )


def final_stage(dockerfile: str) -> str:
    marker = "\nFROM "
    index = dockerfile.rfind(marker)
    if index == -1:
        return dockerfile
    return dockerfile[index + 1 :]


if __name__ == "__main__":
    raise SystemExit(main())
