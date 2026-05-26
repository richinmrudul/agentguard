from pathlib import Path

import yaml


def test_composite_action_metadata_is_valid() -> None:
    action_path = Path("action/action.yml")
    entrypoint_path = Path("action/entrypoint.sh")

    assert action_path.exists()
    assert entrypoint_path.exists()

    metadata = yaml.safe_load(action_path.read_text(encoding="utf-8"))

    assert metadata["name"] == "AgentGuard"
    assert metadata["runs"]["using"] == "composite"
    assert set(metadata["inputs"]) >= {
        "config",
        "base",
        "head",
        "github-summary",
        "allow-fail-result",
    }
    assert metadata["inputs"]["config"]["default"] == "agentguard.yaml"
    assert metadata["inputs"]["head"]["default"] == "HEAD"
    assert metadata["inputs"]["github-summary"]["default"] == "true"

    entrypoint = entrypoint_path.read_text(encoding="utf-8")
    assert "set -euo pipefail" in entrypoint
    assert "agentguard ci" in entrypoint
    assert "--github-summary" in entrypoint
