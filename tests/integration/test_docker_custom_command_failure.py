import io
import json
import threading
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.core.orchestrator import run_benchmark
from agentguard.guard.filesystem import GuardMode
from agentguard.history.store import HistoryRecord
from agentguard.sandbox.docker_identity import DockerImageIdentity
from agentguard.sandbox.docker_runner import DockerCommandRunner


@pytest.fixture(autouse=True)
def _established_docker_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        DockerCommandRunner,
        "_prepare_container_identity",
        lambda self, *_args, **_kwargs: DockerImageIdentity(
            configured_reference=self.sandbox.image or "",
            local_image_id="sha256:" + "1" * 64,
            executed_image_id="sha256:" + "1" * 64,
            platform="linux/amd64",
            cache_status="present",
        ),
    )


class _FakeProcess:
    def __init__(self, *, returncode: int, stdout: str, stderr: str) -> None:
        self.returncode = returncode
        self.stdout = io.BytesIO(stdout.encode())
        self.stderr = io.BytesIO(stderr.encode())
        self.pid = 12345

    def wait(self, timeout=None):
        return self.returncode

    def poll(self):
        return self.returncode


def test_docker_custom_command_failure_preserves_controlled_evidence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    repo = tmp_path / "template"
    (repo / "src").mkdir(parents=True)
    (repo / "src/app.py").write_text("VALUE = 'old'\n", encoding="utf-8")
    secret = "docker-failure-canary"
    version_secret = "docker-version-failure-canary"
    config = tmp_path / "docker-failure.yaml"
    config.write_text(
        "\n".join(
            [
                "task_id: docker_failure_evidence",
                "description: Preserve controlled Docker failure evidence.",
                f"repo_template: {repo}",
                f"agent_command: python agent.py --token {secret}",
                "agent_version_command:",
                "  - agent",
                "  - --version",
                "  - --token",
                f"  - {version_secret}",
                "agent_environment:",
                f"  API_TOKEN: {secret}",
                "test_command: python -c pass",
                "command_timeout_seconds: 3",
                "max_output_bytes: 512",
                "sandbox:",
                "  type: docker",
                "  image: python:3.11-slim",
                "allowed_paths:",
                "  - src/**",
                "expected_modified_files:",
                "  min: 0",
                "  max: 2",
                "unsafe_commands: []",
                "policy:",
                "  tests_pass:",
                "    severity: error",
                "diff_limits:",
                "  max_files_changed: 2",
                "secret_patterns: []",
                "",
            ]
        ),
        encoding="utf-8",
    )
    recorded: list[HistoryRecord] = []
    monkeypatch.setattr(
        "agentguard.core.orchestrator.record_history",
        recorded.append,
    )
    monkeypatch.setattr(
        "agentguard.provenance.manifest._docker_version",
        lambda: None,
    )

    def fake_popen(command, **kwargs):
        checkout = str(next((tmp_path / ".agentguard" / "runs").glob("*/repo")))
        if "--version" in command:
            return _FakeProcess(
                returncode=127,
                stdout="",
                stderr=(
                    f"version failure {version_secret} "
                    f"{checkout}\x1b[31m"
                ),
            )
        (Path(checkout) / "src/app.py").write_text(
            f"VALUE = 'changed'\n# {secret}\n",
            encoding="utf-8",
        )
        return _FakeProcess(
            returncode=7,
            stdout=(
                f"Authorization: Bearer {secret}\n"
                f"checkout={checkout}\x1b[31m"
            ),
            stderr=f"https://user:{secret}@example.invalid/failure",
        )

    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        fake_popen,
    )

    with pytest.warns(RuntimeWarning, match="version detection"):
        result = run_benchmark(
            config,
            "custom-command",
            guard_mode=GuardMode.AUDIT,
            guard_poll_interval_seconds=0.01,
        )

    assert result.result == "FAIL"
    assert result.test_result.exit_code == 7
    assert result.test_result.command.startswith("docker agent:")
    assert result.diff_summary.modified_files == ["src/app.py"]
    assert "[REDACTED]" in result.diff_summary.unified_diff
    assert any(
        event.event_type == "tests_skipped" for event in result.timeline
    )
    assert result.report_paths.command_log is not None
    assert result.report_paths.trace is not None
    assert result.report_paths.manifest is not None
    artifact_paths = [
        result.report_paths.command_log,
        result.report_paths.json,
        result.report_paths.markdown,
        result.report_paths.trace,
        result.report_paths.manifest,
    ]
    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in artifact_paths
    )
    assert secret not in combined
    assert version_secret not in combined
    assert str(result.repo_dir.resolve()) not in combined
    assert "Authorization: [REDACTED]" in combined
    assert "\x1b" not in combined
    assert "\\x1b" in combined
    command_log = json.loads(
        result.report_paths.command_log.read_text(encoding="utf-8")
    )
    failed_agent = next(
        event
        for event in command_log
        if event["command_text"].startswith("docker agent:")
    )
    assert failed_agent["exit_code"] == 7
    assert failed_agent["cwd"] == "[REPOSITORY]"
    assert any(
        event["command_text"].startswith("docker agent version:")
        for event in command_log
    )
    assert recorded and recorded[0].result == "FAIL"
    assert not {
        "agentguard-filesystem-guard",
        "agentguard-command-guard",
    }.intersection(
        thread.name for thread in threading.enumerate() if thread.is_alive()
    )

    setup_canary = "raw-daemon-failure\x1b[31m"
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        lambda *_args, **_kwargs: _FakeProcess(
            returncode=125,
            stdout="",
            stderr=setup_canary,
        ),
    )
    with pytest.warns(RuntimeWarning, match="version detection"):
        cli_result = CliRunner().invoke(
            app,
            ["run", str(config), "--agent", "custom-command"],
        )

    assert cli_result.exit_code == 2
    assert "Error: Docker could not start the custom agent container." in (
        cli_result.output
    )
    assert setup_canary not in cli_result.output
    assert secret not in cli_result.output
    assert "Traceback" not in cli_result.output
