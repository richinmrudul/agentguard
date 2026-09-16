import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from agentguard.config.loader import load_config
from agentguard.containment.evidence import (
    canonical_containment_json,
    evidence_from_benchmark_result,
    parse_containment_evidence,
)
from agentguard.core.contained_run import run_contained_agent_command
from agentguard.core.result import (
    BenchmarkResult,
    CommandResult,
    DiffSummary,
    ReportPaths,
    SandboxMetadata,
)
from agentguard.reports.json_report import write_json_report
from agentguard.reports.markdown_report import write_markdown_report
from agentguard.reports.site import _containment_summary
from agentguard.provenance.manifest import (
    AgentGuardIdentity,
    ArtifactIdentity,
    ConfigurationIdentity,
    ExecutionManifest,
    HostIdentity,
    SourceIdentity,
    serialize_manifest,
)
from agentguard.sandbox import docker_preflight
from agentguard.sandbox.docker_identity import DockerImageIdentity
from agentguard.traces.execution import (
    build_execution_trace,
    build_policy_snapshot,
    load_execution_trace,
    serialize_execution_trace,
    verify_execution_trace,
)
from agentguard.traces.replay import reconstruct_replay_evidence


IMAGE = "example.com/team/agent@sha256:" + "a" * 64


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    (source / "hello.txt").write_text("hello\n", encoding="utf-8")
    return source


def _config(tmp_path: Path, **updates) -> Path:
    data = {
        "task_id": "containment_evidence",
        "description": "Containment evidence test.",
        "repo_template": str(_source(tmp_path)),
        "test_command": "true",
        "expected_modified_files": {"min": 0, "max": 2},
        "unsafe_commands": [],
        "sandbox": {"type": "docker", "image": IMAGE, "network": "none"},
        "contained_execution": {
            "version": 1,
            "platform": "linux-docker-engine",
            "network": "none",
            "image_provenance": "digest-required",
            "required_uid": os.geteuid(),
            "required_gid": os.getegid(),
        },
    }
    data.update(updates)
    path = tmp_path / "agentguard.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _image() -> DockerImageIdentity:
    return DockerImageIdentity(
        configured_reference=IMAGE,
        local_image_id="sha256:" + "b" * 64,
        executed_image_id="sha256:" + "b" * 64,
        registry_digest=IMAGE,
        platform="linux/amd64",
        cache_status="present",
    )


def _preflight(_config) -> docker_preflight.DockerPreflightResult:
    return docker_preflight.DockerPreflightResult(
        status=docker_preflight.DockerPreflightStatus.SUPPORTED,
        claim_level="linux-docker-engine",
        supported=True,
        checks=[
            docker_preflight.DockerPreflightCheck(
                name="docker_cli_and_daemon",
                passed=True,
                status="supported",
                diagnostic="ok",
            ),
            docker_preflight.DockerPreflightCheck(
                name="resource_control_probe",
                passed=True,
                status="supported",
                diagnostic="verified",
                evidence={
                    "requested": {
                        "pids_limit": 256,
                        "memory_limit": "512m",
                        "cpu_limit": 1.0,
                    },
                    "inspected": {
                        "container_identity": "matched",
                        "image_identity": "matched",
                        "pids_limit": 256,
                        "memory_bytes": 512 * 1024 * 1024,
                        "cpu": {
                            "requested_cpus": 1.0,
                            "nano_cpus": 1_000_000_000,
                            "representation": "NanoCpus",
                        },
                        "uid_gid": f"{os.geteuid()}:{os.getegid()}",
                        "network": "none",
                        "read_only_rootfs": True,
                        "no_new_privileges": True,
                        "cap_drop_all": True,
                        "tmpfs_paths": ["/tmp", "/agentguard-workspace"],
                        "privileged": False,
                        "host_namespace_sharing": False,
                        "device_exposure": False,
                        "docker_socket_mount": False,
                    },
                },
            )
        ],
        docker_image=_image(),
        evidence={"approved_boundary_constructible": True},
    )


def test_contained_run_writes_canonical_sanitized_evidence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    secret = "AGENTGUARD_SECRET_CANARY_CONTAINMENT"
    config_path = _config(
        tmp_path,
        contained_execution={
            "version": 1,
            "platform": "linux-docker-engine",
            "network": "none",
            "image_provenance": "digest-required",
            "required_uid": os.geteuid(),
            "required_gid": os.getegid(),
            "environment": [
                {
                    "name": "API_TOKEN",
                    "source": "literal",
                    "value": secret,
                    "sensitive": True,
                    "allow_sensitive": True,
                }
            ],
        },
    )
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        _preflight,
    )

    result = run_contained_agent_command(
        config_path,
        ["python", "-c", f"print('{secret}')"],
        runs_root=tmp_path / "runs",
        docker_executor=lambda argv, cwd, timeout_seconds, max_output_bytes: CommandResult(
            "contained-run",
            0,
            secret,
            "",
            0.01,
        ),
    )

    report = json.loads(result.report_path.read_text(encoding="utf-8"))
    evidence = parse_containment_evidence(report["containment_evidence"])
    serialized = canonical_containment_json(evidence)
    assert evidence["execution_mode"] == "contained-run"
    assert evidence["preflight"]["status"] == "supported"
    assert evidence["image"]["registry_digest"] == IMAGE
    assert evidence["environment"]["sensitive_names"] == ["API_TOKEN"]
    assert evidence["environment"]["values_recorded"] is False
    assert evidence["controls"]["tmpfs_paths"] == ["/tmp"]
    assert evidence["controls"]["resource_verification_state"] == "recorded"
    assert evidence["controls"]["requested_resource_controls"]["memory_limit"] == "512m"
    assert evidence["controls"]["verified_resource_controls"]["memory_bytes"] == (
        512 * 1024 * 1024
    )
    assert evidence["controls"]["verified_resource_controls"]["container_identity"] == (
        "matched"
    )
    assert evidence["cleanup"]["overall_complete"] is True
    assert secret not in serialized
    assert str(tmp_path) not in serialized
    assert "docker_argv" not in serialized


def test_containment_evidence_rejects_bad_enums_and_identity() -> None:
    evidence = evidence_from_benchmark_result(
        BenchmarkResult(
            task_id="task",
            agent="agent",
            result="PASS",
            score=100,
            config_path=Path("agentguard.yaml"),
            run_dir=Path(".agentguard/runs/run"),
            repo_dir=Path("."),
            test_result=CommandResult("true", 0, "", "", 0.01),
            diff_summary=DiffSummary([], [], [], 0, 0, ""),
            check_results=[],
            report_paths=ReportPaths(
                json=Path("report.json"),
                markdown=Path("report.md"),
            ),
        )
    ).to_dict()
    parse_containment_evidence(evidence)
    bad_status = json.loads(json.dumps(evidence))
    bad_status["execution"]["status"] = "definitely"
    with pytest.raises(ValueError, match="execution status"):
        parse_containment_evidence(bad_status)
    bad_image = json.loads(json.dumps(evidence))
    bad_image["image"] = {
        "state": "recorded",
        "configured_reference": IMAGE,
        "registry_digest": IMAGE,
        "local_image_id": "sha256:" + "c" * 64,
        "container_bound_image_id": "sha256:" + "d" * 64,
        "platform": "linux/amd64",
        "pull_policy": "docker-default",
        "cache_status": "present",
    }
    with pytest.raises(ValueError, match="image"):
        parse_containment_evidence(bad_image)


def test_report_markdown_and_trace_share_same_canonical_evidence(
    tmp_path: Path,
) -> None:
    config_path = _config(tmp_path)
    config = load_config(config_path)
    report_paths = ReportPaths(
        json=tmp_path / "report.json",
        markdown=tmp_path / "report.md",
        trace=tmp_path / "trace.jsonl",
    )
    result = BenchmarkResult(
        task_id="task",
        agent="agent",
        result="PASS",
        score=100,
        config_path=config_path,
        run_dir=tmp_path,
        repo_dir=tmp_path,
        test_result=CommandResult("true", 0, "", "", 0.01, docker_image=_image()),
        diff_summary=DiffSummary([], [], [], 0, 0, ""),
        check_results=[],
        report_paths=report_paths,
        sandbox=SandboxMetadata(
            type="docker",
            timeout_seconds=10,
            max_output_bytes=4096,
            network="none",
            configured_image=IMAGE,
        ),
    )
    evidence = evidence_from_benchmark_result(result).to_dict()
    result = replace(result, containment_evidence=evidence)

    json_report = json.loads(write_json_report(result, tmp_path).read_text())
    markdown = write_markdown_report(result, tmp_path).read_text(encoding="utf-8")
    trace = build_execution_trace(
        result,
        created_at="2026-09-14T00:00:00+00:00",
        configuration_hash="a" * 64,
        agentguard_version="0.3.1",
        agentguard_commit=None,
        agent_version=None,
        policy_summary="{}",
        sandbox_summary="{}",
        source_report_id="report.json",
        source_manifest_id=None,
        policy_snapshot=build_policy_snapshot(config),
    )
    containment_event = next(
        event for event in trace.events if event.event_type == "containment_evidence"
    )

    assert canonical_containment_json(json_report["containment_evidence"]) == (
        canonical_containment_json(containment_event.payload)
    )
    assert "## Containment Evidence" in markdown
    assert verify_execution_trace(report_paths.trace).exit_code == 2
    serialized = serialize_execution_trace(trace)
    assert "containment_evidence" in serialized
    loaded_path = tmp_path / "trace.jsonl"
    loaded_path.write_text(serialized, encoding="utf-8")
    assert verify_execution_trace(loaded_path).exit_code == 0
    assert load_execution_trace(loaded_path).header.schema_version == 3
    assert reconstruct_replay_evidence(trace).containment_evidence == evidence


def test_failed_preflight_evidence_redacts_command_credentials_and_paths(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(tmp_path)
    preflight = docker_preflight.DockerPreflightResult(
        status=docker_preflight.DockerPreflightStatus.UNAVAILABLE,
        claim_level="none",
        supported=False,
        checks=[],
        evidence={},
    )
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda _config: preflight,
    )

    result = run_contained_agent_command(
        config_path,
        ["tool", "--token", "super-secret", str(tmp_path / "private")],
        runs_root=tmp_path / "runs",
    )

    report = json.loads(result.report_path.read_text(encoding="utf-8"))
    serialized = canonical_containment_json(report["containment_evidence"])
    assert report["containment_evidence"]["execution"]["status"] == "preflight_blocked"
    assert report["containment_evidence"]["cleanup"]["container_status"] == "not_created"
    assert "super-secret" not in serialized
    assert str(tmp_path) not in serialized
    assert "[REDACTED]" in serialized
    assert "[REDACTED_PATH]" in serialized


def test_manifest_serializes_canonical_containment_evidence() -> None:
    evidence = evidence_from_benchmark_result(
        BenchmarkResult(
            task_id="task",
            agent="agent",
            result="PASS",
            score=100,
            config_path=Path("agentguard.yaml"),
            run_dir=Path(".agentguard/runs/run"),
            repo_dir=Path("."),
            test_result=CommandResult("true", 0, "", "", 0.01),
            diff_summary=DiffSummary([], [], [], 0, 0, ""),
            check_results=[],
            report_paths=ReportPaths(
                json=Path("report.json"),
                markdown=Path("report.md"),
            ),
        )
    ).to_dict()
    manifest = ExecutionManifest(
        execution_id="run",
        execution_type="run",
        created_at="2026-09-14T00:00:00+00:00",
        completed_at="2026-09-14T00:00:01+00:00",
        duration_seconds=1.0,
        agentguard=AgentGuardIdentity(version="0.3.1"),
        host=HostIdentity("Linux", "x86_64", "3.9"),
        source=SourceIdentity(repository="${REPOSITORY_ROOT}"),
        configuration=ConfigurationIdentity("${CONFIG_ROOT}", "a" * 64, {}),
        agent=None,
        benchmarks=[],
        policies=[],
        artifacts=ArtifactIdentity(None, None),
        containment_evidence=evidence,
    )

    payload = json.loads(serialize_manifest(manifest))
    assert canonical_containment_json(payload["containment_evidence"]) == (
        canonical_containment_json(evidence)
    )
    malformed = replace(manifest, containment_evidence={"schema": "bad"})
    with pytest.raises(ValueError, match="fields are invalid"):
        serialize_manifest(malformed)


def test_static_site_renders_only_allowlisted_containment_summary() -> None:
    evidence = evidence_from_benchmark_result(
        BenchmarkResult(
            task_id="task",
            agent="agent",
            result="PASS",
            score=100,
            config_path=Path("agentguard.yaml"),
            run_dir=Path(".agentguard/runs/run"),
            repo_dir=Path("."),
            test_result=CommandResult("true", 0, "", "", 0.01),
            diff_summary=DiffSummary([], [], [], 0, 0, ""),
            check_results=[],
            report_paths=ReportPaths(Path("report.json"), Path("report.md")),
        )
    ).to_dict()

    html = _containment_summary(evidence)
    assert "not_applicable" in html
    assert "Environment" not in html
    assert "command" not in html
    malformed = _containment_summary(
        {"schema": "bad", "secret": "AGENTGUARD_SECRET_CANARY_SITE"}
    )
    assert "malformed or unsupported" in malformed
    assert "AGENTGUARD_SECRET_CANARY_SITE" not in malformed
