import json
from pathlib import Path

import pytest
import yaml

from agentguard.evaluation.study_plan import (
    ContainedStudyPlanOptions,
    build_contained_study_plan,
    serialize_contained_study_plan,
)
from agentguard.evaluation.study_runner import ContainedStudyRunnerOptions, run_contained_study_plan
from tests.integration.test_contained_run_docker import (
    _ci_safe_digest_pinned_image,
    _platform_claim,
    _require_docker_available,
)


def _digest(data: dict[str, object]) -> str:
    cloned = dict(data)
    cloned["plan_digest"] = None
    return __import__("hashlib").sha256(
        json.dumps(cloned, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


@pytest.mark.docker
def test_contained_study_runner_executes_read_only_control_through_hosted_docker(
    tmp_path: Path,
) -> None:
    _require_docker_available()
    image = _ci_safe_digest_pinned_image()
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        yaml.safe_dump(
            {
                "schema": "agentguard.contained-agent-profile",
                "schema_version": 1,
                "id": "offline-control",
                "display_label": "Offline Control",
                "image": image,
                "argv": ["true"],
                "capabilities": ["read-only"],
                "limits": {
                    "timeout_seconds": 30,
                    "cpu_limit": 1.0,
                    "memory_limit": "128m",
                    "pids_limit": 64,
                    "max_output_bytes": 4096,
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    plan = build_contained_study_plan(
        ContainedStudyPlanOptions(
            profile_paths=[profile],
            fixture_ids=["read-only-control"],
            trials=1,
        )
    )
    data = json.loads(serialize_contained_study_plan(plan))
    data["approval_requirements"] = []
    data["plan_digest"] = _digest(data)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(
        json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    result = run_contained_study_plan(
        ContainedStudyRunnerOptions(
            plan_path=plan_path,
            profile_paths=[profile],
            output_dir=tmp_path / "study-runs",
            platform=_platform_claim(),
        )
    )

    assert result.completed == 1
    state = json.loads(result.state_path.read_text(encoding="utf-8"))
    trial_state = next(iter(state["trials"].values()))
    trial_result = json.loads((result.run_dir / trial_state["result_path"]).read_text(encoding="utf-8"))
    contained_report = json.loads(
        (result.run_dir / trial_state["contained_run_report"]).read_text(encoding="utf-8")
    )
    assert trial_result["contained_run"]["result"] == "PASS"
    assert contained_report["containment_evidence"]["execution_mode"] == "contained-run"
    assert contained_report["containment_evidence"]["preflight"]["status"] in {
        "supported",
        "experimental",
    }
    assert contained_report["containment_evidence"]["environment"]["values_recorded"] is False
    assert contained_report["containment_evidence"]["cleanup"]["overall_complete"] is True
    assert str(tmp_path) not in json.dumps(state, sort_keys=True)
