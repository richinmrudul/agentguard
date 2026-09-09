from pathlib import Path


def test_contained_execution_contract_documents_required_boundaries() -> None:
    page = Path("docs/contained-execution.md").read_text(encoding="utf-8")
    architecture = Path("docs/architecture.md").read_text(encoding="utf-8")
    mkdocs = Path("mkdocs.yml").read_text(encoding="utf-8")
    combined = f"{page}\n{architecture}".lower()
    normalized = " ".join(combined.split())

    required_phrases = [
        "linux docker engine is the authoritative contained-execution platform",
        "docker desktop is experimental and carries reduced claims",
        "the host operating system, host kernel",
        "the docker daemon api",
        "host networking",
        "privileged containers",
        "docker socket mounts",
        "host device exposure",
        "host pid, ipc, user, uts, cgroup, or other namespace sharing",
        "the default network mode is `none`",
        "bridge networking is accepted only as an explicit v1 opt-in",
        "deterministic docker argv list directly",
        "does not accept raw docker flag strings",
        "evidence outside the repository mounted for the untrusted agent",
        "fail before launching the agent",
        "container escape",
        "malicious or vulnerable host kernels",
        "existing execution modes remain unchanged",
        "future contained-agent application-level boundary",
        "`untrusted-agent` preset remains unavailable",
        "contained workspace lifecycle foundation",
        "the original repository is never mounted as the writable agent workspace",
        "without inheriting `.git` control metadata",
        "fixed baseline snapshot",
        "writable paths must be unique and non-overlapping",
        "`.` is accepted only as the sole writable path",
        "agent-created `.git` control metadata inside the prepared workspace",
        "causes capture to fail closed",
        "regular-file copy uses a copy-time identity check",
        "user-visible errors do not expose private absolute host paths or credentials",
        "does not launch an agent",
    ]

    for phrase in required_phrases:
        assert phrase in normalized

    unsupported_claims = [
        "fully sandboxed",
        "certified sandbox",
        "guarantees safe behavior",
        "hostile-code containment",
        "prevents every secret leak",
        "docker desktop provides linux docker engine equivalent containment",
    ]
    for claim in unsupported_claims:
        assert claim not in normalized

    assert "Contained Execution Contract: contained-execution.md" in mkdocs
