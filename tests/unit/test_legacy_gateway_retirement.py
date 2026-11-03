import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from agentguard.evaluation.retired_runtime_images import (
    RETIRED_GATEWAY_DIGEST,
    RETIRED_GATEWAY_REPOSITORY,
    is_retired_gateway_reference,
    validate_retirement_record,
)
from agentguard.evaluation.study_runner import (
    ContainedStudyRunnerError,
    ContainedStudyRunnerOptions,
    _validate_execution_mode,
)
from agentguard.evaluation.live_egress_gateway import LiveStudyEgressError, run_live_study_egress_trial
from scripts.stage1_publication_manifest import main as publication_main


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github/workflows"


def _workflow(path: str) -> dict:
    data = yaml.safe_load((WORKFLOWS / path).read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_published_legacy_subject_is_retired_not_rejected(tmp_path: Path) -> None:
    path = ROOT / "runtime-images/retired-runtime-subjects.json"
    validate_retirement_record(path)
    record = json.loads(path.read_text(encoding="utf-8"))["subjects"][0]
    assert record["repository"] == RETIRED_GATEWAY_REPOSITORY
    assert record["digest"] == RETIRED_GATEWAY_DIGEST
    assert record["status"] == "retired"
    assert record["eligible_for_new_study"] is False
    rejected = (ROOT / "runtime-images/rejected-publications.json").read_text(encoding="utf-8")
    assert RETIRED_GATEWAY_DIGEST not in rejected
    for change in ({"eligible_for_new_study": True}, {"status": "approved"}, {"digest": "sha256:" + "a" * 64}):
        altered = json.loads(path.read_text(encoding="utf-8"))
        altered["subjects"][0].update(change)
        candidate = tmp_path / "altered.json"
        candidate.write_text(json.dumps(altered), encoding="utf-8")
        with pytest.raises(ValueError, match="differs"):
            validate_retirement_record(candidate)


def test_every_legacy_gateway_tag_or_digest_is_ineligible() -> None:
    assert is_retired_gateway_reference(RETIRED_GATEWAY_REPOSITORY + "@" + RETIRED_GATEWAY_DIGEST)
    assert is_retired_gateway_reference(RETIRED_GATEWAY_REPOSITORY + ":latest")
    assert is_retired_gateway_reference(RETIRED_GATEWAY_REPOSITORY + ":main")
    assert is_retired_gateway_reference(RETIRED_GATEWAY_REPOSITORY + ":shortsha")
    assert is_retired_gateway_reference(RETIRED_GATEWAY_REPOSITORY + ":" + "0" * 40)
    assert not is_retired_gateway_reference("ghcr.io/richinmrudul/agentguard/stage1-metering-gateway@" + RETIRED_GATEWAY_DIGEST)


def test_runner_rejects_legacy_gateway_before_plan_or_docker(tmp_path: Path) -> None:
    options = ContainedStudyRunnerOptions(
        plan_path=tmp_path / "missing-plan.json",
        profile_paths=[],
        execution_mode="study-egress",
        egress_policy=object(),  # Only presence is inspected at this preflight boundary.
        gateway_image=RETIRED_GATEWAY_REPOSITORY + "@" + RETIRED_GATEWAY_DIGEST,
        authorization_path=tmp_path / "missing-authorization.json",
    )
    with pytest.raises(ContainedStudyRunnerError, match="Retired Stage 1 gateway"):
        _validate_execution_mode(options)


def test_direct_egress_runner_rejects_before_policy_or_docker() -> None:
    request = SimpleNamespace(gateway_image=RETIRED_GATEWAY_REPOSITORY + "@" + RETIRED_GATEWAY_DIGEST)
    with pytest.raises(LiveStudyEgressError, match="Retired Stage 1 gateway"):
        run_live_study_egress_trial(request)


def test_publication_prepare_refuses_retired_gateway_without_writing(tmp_path: Path) -> None:
    output = tmp_path / "manifest.json"
    result = publication_main([
        "prepare", "--root", str(tmp_path), "--source-commit", "0" * 40,
        "--workflow", "retired", "--run-id", "1", "--run-attempt", "1",
        "--gateway-image", RETIRED_GATEWAY_REPOSITORY + ":" + "0" * 40,
        "--agent-image", "ghcr.io/richinmrudul/agentguard/stage1-codex-agent:" + "0" * 40,
        "--output", str(output),
    ])
    assert result == 1
    assert not output.exists()


def test_legacy_build_and_publisher_are_unreachable_from_environment_variable() -> None:
    build = _workflow("stage1-runtime-images.yml")["jobs"]["build-validate"]
    publish = _workflow("stage1-runtime-images-publish.yml")["jobs"]
    assert build["if"] == "${{ false }}"
    assert publish["prepare"]["if"].split()[0] == "false"
    assert publish["publish"]["if"].split()[0] == "false"
    assert "vars.STAGE1_RUNTIME_PUBLICATION_ENABLED" in publish["publish"]["if"]


def test_active_agent_and_compiled_candidate_gates_still_scan() -> None:
    agent = _workflow("stage1-agent-image.yml")
    candidate = _workflow("stage1-compiled-metering-security.yml")
    assert "pull_request" in agent[True]
    assert "pull_request" in candidate[True]
    for workflow in (agent, candidate):
        assert workflow["permissions"] == {"contents": "read"}
    agent_text = (WORKFLOWS / "stage1-agent-image.yml").read_text(encoding="utf-8")
    candidate_text = (WORKFLOWS / "stage1-compiled-metering-security.yml").read_text(encoding="utf-8")
    assert "for build in a b" in agent_text
    assert "AGENT_REVIEWED_IMAGE_DIGEST" in agent_text
    assert "normalized_sbom_package_rows" in agent_text
    assert "summarize_trivy_high_critical" in agent_text
    assert 'assert not scans[0]["findings"]' in agent_text
    assert "if: always()" in agent_text
    assert "runtime-images/stage1-metering-rust" in candidate_text
    assert "packages: write" not in agent_text + candidate_text
    assert "docker push" not in agent_text + candidate_text
