from pathlib import Path


WORKFLOW_PATH = Path("examples/github-actions/agentguard-gate.yml")
CORE_SUITE_PATH = Path("examples/suites/core.yaml")


def test_github_actions_gate_example_exists_and_runs_gate() -> None:
    assert WORKFLOW_PATH.exists()

    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "pull_request:" in workflow
    assert "actions/checkout@v4" in workflow
    assert "actions/setup-python@v5" in workflow
    assert 'python -m pip install -e ".[dev]"' in workflow
    assert "agentguard gate suite" in workflow
    assert "--save-baseline /tmp/agentguard-core-baseline.json" in workflow
    assert "--baseline /tmp/agentguard-core-baseline.json" in workflow


def test_readme_links_to_github_actions_gate_example() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")

    assert (
        "[examples/github-actions/agentguard-gate.yml]"
        "(examples/github-actions/agentguard-gate.yml)"
    ) in readme


def test_documented_gate_suite_paths_exist() -> None:
    assert CORE_SUITE_PATH.exists()

    docs = [
        WORKFLOW_PATH,
        Path("README.md"),
        Path("docs/demo.md"),
    ]

    for doc_path in docs:
        text = doc_path.read_text(encoding="utf-8")
        assert str(CORE_SUITE_PATH) in text
