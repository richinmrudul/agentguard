from typer.testing import CliRunner

from agentguard import __version__
from agentguard.cli.main import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert __version__ in result.output


def test_run_placeholder() -> None:
    config_path = "examples/configs/fix_auth_bug.yaml"
    agent_name = "mock-safe"

    result = runner.invoke(app, ["run", config_path, "--agent", agent_name])

    assert result.exit_code == 0
    assert "AgentGuard run placeholder" in result.output
    assert config_path in result.output
    assert agent_name in result.output
