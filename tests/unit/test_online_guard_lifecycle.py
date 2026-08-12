import threading
import time
from pathlib import Path

import pytest

import agentguard.core.orchestrator as orchestrator
from agentguard.guard.filesystem import GuardMode


GUARD_THREAD_NAMES = {
    "agentguard-filesystem-guard",
    "agentguard-command-guard",
}


class RaisingAgent:
    def __init__(self, error: BaseException) -> None:
        self.error = error

    def run(self, *_args, **_kwargs) -> None:
        raise self.error


class SuccessfulAgent:
    def run(self, *_args, **_kwargs) -> None:
        return None


@pytest.mark.parametrize(
    "error",
    [RuntimeError("agent failed"), KeyboardInterrupt("agent interrupted")],
)
def test_agent_base_exception_stops_both_online_guards(
    tmp_path: Path,
    monkeypatch,
    error: BaseException,
) -> None:
    monkeypatch.chdir(tmp_path)
    config = _write_config(tmp_path)
    monkeypatch.setattr(
        orchestrator,
        "_agent_for_config",
        lambda *_args: RaisingAgent(error),
    )

    with pytest.raises(BaseException) as caught:
        orchestrator.run_benchmark(
            config,
            "mock-safe",
            guard_mode=GuardMode.AUDIT,
            guard_poll_interval_seconds=0.01,
        )

    assert caught.value is error
    _assert_no_guard_threads()


@pytest.mark.parametrize("guard_name", ["filesystem", "command"])
def test_partial_guard_start_is_cleaned_up(
    tmp_path: Path,
    monkeypatch,
    guard_name: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    config = _write_config(tmp_path)
    error = RuntimeError(f"{guard_name} startup failed")
    guard_type = (
        orchestrator.RuntimeFilesystemGuard
        if guard_name == "filesystem"
        else orchestrator.RuntimeCommandGuard
    )
    original_start = guard_type.start

    def start_then_raise(self) -> None:
        original_start(self)
        raise error

    monkeypatch.setattr(guard_type, "start", start_then_raise)

    with pytest.raises(RuntimeError) as caught:
        orchestrator.run_benchmark(
            config,
            "mock-safe",
            guard_mode=GuardMode.AUDIT,
            guard_poll_interval_seconds=0.01,
        )

    assert caught.value is error
    _assert_no_guard_threads()


def test_cleanup_failures_are_sanitized_without_replacing_primary_error(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    config = _write_config(tmp_path)
    primary = RuntimeError("primary agent failure")
    canary = "cleanup-secret-canary"
    monkeypatch.setattr(
        orchestrator,
        "_agent_for_config",
        lambda *_args: RaisingAgent(primary),
    )
    for guard_type in (
        orchestrator.RuntimeFilesystemGuard,
        orchestrator.RuntimeCommandGuard,
    ):
        original_stop = guard_type.stop

        def stop_then_raise(self, _stop=original_stop):
            _stop(self)
            raise ValueError(canary)

        monkeypatch.setattr(guard_type, "stop", stop_then_raise)

    with pytest.warns(RuntimeWarning) as recorded:
        with pytest.raises(RuntimeError) as caught:
            orchestrator.run_benchmark(
                config,
                "mock-safe",
                guard_mode=GuardMode.AUDIT,
                guard_poll_interval_seconds=0.01,
            )

    assert caught.value is primary
    warning_text = "\n".join(str(item.message) for item in recorded)
    assert "2 failure(s): ValueError, ValueError" in warning_text
    assert canary not in warning_text
    _assert_no_guard_threads()


def test_post_agent_scan_failure_still_stops_both_guards(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    config = _write_config(tmp_path)
    error = RuntimeError("final scan failed")
    monkeypatch.setattr(
        orchestrator,
        "_agent_for_config",
        lambda *_args: SuccessfulAgent(),
    )
    monkeypatch.setattr(
        orchestrator.RuntimeFilesystemGuard,
        "scan_once",
        lambda _self: (_ for _ in ()).throw(error),
    )

    with pytest.raises(RuntimeError) as caught:
        orchestrator.run_benchmark(
            config,
            "mock-safe",
            guard_mode=GuardMode.AUDIT,
            guard_poll_interval_seconds=1.0,
        )

    assert caught.value is error
    _assert_no_guard_threads()


def test_repeated_failed_runs_do_not_accumulate_guard_threads(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    config = _write_config(tmp_path)
    monkeypatch.setattr(
        orchestrator,
        "_agent_for_config",
        lambda *_args: RaisingAgent(RuntimeError("matrix row failed")),
    )

    for _ in range(5):
        with pytest.raises(RuntimeError, match="matrix row failed"):
            orchestrator.run_benchmark(
                config,
                "mock-safe",
                guard_mode=GuardMode.AUDIT,
                guard_poll_interval_seconds=0.01,
            )
        _assert_no_guard_threads()


def _assert_no_guard_threads() -> None:
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        alive = [
            thread
            for thread in threading.enumerate()
            if thread.name in GUARD_THREAD_NAMES and thread.is_alive()
        ]
        if not alive:
            return
        time.sleep(0.01)
    raise AssertionError(
        "online guard threads remain alive: "
        + ", ".join(thread.name for thread in alive)
    )


def _write_config(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "src/app.py").write_text("VALUE = 'old'\n", encoding="utf-8")
    (repo / "tests/test_app.py").write_text(
        "def test_app():\n    assert True\n", encoding="utf-8"
    )
    config = tmp_path / "guard-lifecycle.yaml"
    config.write_text(
        "\n".join(
            [
                "task_id: guard_lifecycle",
                "description: Online guard lifecycle test.",
                f"repo_template: {repo}",
                "test_command: python -c pass",
                "sandbox:",
                "  type: local",
                "allowed_paths:",
                "  - src/**",
                "test_paths:",
                "  - tests/**",
                "expected_modified_files:",
                "  min: 0",
                "  max: 10",
                "unsafe_commands: []",
                "policy:",
                "  tests_pass:",
                "    severity: error",
                "diff_limits:",
                "  max_files_changed: 10",
                "secret_patterns: []",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return config
