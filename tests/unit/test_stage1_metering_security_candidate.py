"""The replacement-gateway candidate remains mock-only and security-gated."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentguard.evaluation.runtime_images import RuntimeImageError
from scripts.stage1_metering_security_evidence import trivy_rows


ROOT = Path(__file__).parents[2]


def test_candidate_has_pinned_base_and_mock_only_entrypoint() -> None:
    dockerfile = (ROOT / "runtime-images/stage1-metering/Dockerfile.security-candidate").read_text()
    assert "gcr.io/distroless/python3-debian13:nonroot@sha256:ab7db456" in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert 'ENTRYPOINT ["/usr/bin/python3", "/stage1-security-candidate"]' in dockerfile
    assert "stage1_live_credential.py" in dockerfile
    assert "stage1_live_transport.py" in dockerfile
    assert "stage1_study_ledger.py" in dockerfile
    assert " apt-get " not in dockerfile
    assert " pip install " not in dockerfile
    assert " curl " not in dockerfile
    entrypoint = (ROOT / "runtime-images/stage1-metering/b1_mock_gateway.py").read_text()
    assert 'STAGE1_B1_MOCK_ONLY") != "true"' in entrypoint


def test_hosted_candidate_scan_is_retained_before_fail_closed_policy() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    build = workflow.index("Build and inspect metering-gateway security candidate twice")
    integration = workflow.index("Prove candidate image against local TLS mock")
    upload = workflow.index("Retain raw candidate evidence even on failure")
    policy = workflow.index("Fail closed on unreviewed candidate HIGH or CRITICAL")
    assert build < integration < upload < policy
    assert "if: always()" in workflow[upload:policy]
    assert "stage1_metering_security_evidence.py" in workflow[policy:]
    assert "--enforce" in workflow[policy:]
    script = (ROOT / "scripts/stage1_metering_security_build.sh").read_text()
    assert "for build in a b" in script
    assert "--no-cache --pull=false --network=none --platform linux/amd64" in script
    assert "--severity HIGH,CRITICAL" in script
    assert "--exit-code 0" in script
    assert "vulnerability-exceptions" not in script


def test_trivy_rows_preserve_exact_package_and_fixability() -> None:
    finding = {
        "VulnerabilityID": "CVE-2026-12345", "Severity": "HIGH",
        "PkgName": "libexample", "InstalledVersion": "1.0", "FixedVersion": "1.1",
        "SrcName": "example", "Status": "fixed",
    }
    document = {"Results": [{"Type": "deb", "Target": "/work/a.image.tar (debian 13.7)", "Vulnerabilities": [finding]}]}
    rows = trivy_rows(document, "a")
    assert rows == [{
        "cve": "CVE-2026-12345", "severity": "HIGH", "package": "libexample",
        "installed_version": "1.0", "fixed_version": "1.1", "status": "fixed",
        "source_package": "example", "result_type": "deb", "target": "candidate-image (debian 13.7)",
    }]
    assert json.loads(json.dumps(rows)) == rows
    document["Results"][0]["Target"] = "/work/b.image.tar (debian 13.7)"
    assert trivy_rows(document, "b") == rows
    with pytest.raises(RuntimeImageError):
        trivy_rows(document, "a")


@pytest.mark.parametrize("document", [
    {}, {"Results": {}}, {"Results": [None]},
    {"Results": [{"Vulnerabilities": {}}]},
    {"Results": [{"Vulnerabilities": [None]}]},
    {"Results": [{"Vulnerabilities": [{"Severity": "HIGH"}]}]},
])
def test_malformed_scan_fails_closed(document: dict) -> None:
    with pytest.raises(RuntimeImageError):
        trivy_rows(document, "a")
