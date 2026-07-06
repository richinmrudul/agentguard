import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

import yaml

from agentguard.config.loader import load_config
from agentguard.core.suite import load_suite_config


FAKE_SHOWCASE_SECRET = "AGENTGUARD_SHOWCASE_SECRET_EXAMPLE"


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _load_yaml(path: str) -> dict:
    return yaml.safe_load(_read(path))


def _command_blocks(markdown: str) -> list[str]:
    return re.findall(r"```(?:bash|yaml)\n(.*?)```", markdown, flags=re.DOTALL)


def test_demo_assets_exist_and_reference_required_commands() -> None:
    demo_doc = Path("docs/demo.md")
    demo_script = Path("scripts/demo.sh")
    readme = Path("README.md")

    assert demo_doc.exists()
    assert demo_script.exists()
    assert Path("docs/showcase.md").exists()
    assert Path("examples/showcase/showcase.yaml").exists()
    assert Path("scripts/showcase_demo.sh").exists()

    script = demo_script.read_text(encoding="utf-8")
    assert "set -euo pipefail" in script
    assert "--allow-fail-result" in script
    assert "--allow-failures" in script

    assert "docs/demo.md" in readme.read_text(encoding="utf-8")
    assert "docs/showcase.md" in readme.read_text(encoding="utf-8")


def test_resume_demo_selects_a_portable_python_interpreter() -> None:
    script = _read("scripts/resume_demo.sh")

    assert "AGENTGUARD_PYTHON" in script
    assert ".venv/bin/python" in script
    assert "PYTHON_BIN=python3" in script
    assert '"$PYTHON_BIN" - <<' in script


def test_readme_links_core_docs() -> None:
    readme = _read("README.md")

    for doc_path in [
        "docs/architecture.md",
        "docs/demo.md",
        "docs/benchmarks.md",
    ]:
        assert Path(doc_path).exists()
        assert f"({doc_path})" in readme


def test_benchmark_docs_match_registry_ids_and_categories() -> None:
    docs = _read("docs/benchmarks.md")
    registry = _load_yaml("examples/benchmarks/registry.yaml")
    benchmarks = registry["benchmarks"]

    for benchmark in benchmarks:
        row_prefix = f"| `{benchmark['id']}` | `{benchmark['category']}` |"
        assert row_prefix in docs

    documented_rows = re.findall(r"^\| `([^`]+)` \| `([^`]+)` \|", docs, re.M)
    documented = {(benchmark_id, category) for benchmark_id, category in documented_rows}
    registered = {
        (benchmark["id"], benchmark["category"]) for benchmark in benchmarks
    }

    assert documented == registered

    for benchmark in benchmarks:
        contract_path = Path(benchmark["contract"])
        assert contract_path.exists()
        relative_contract = Path("..") / contract_path
        assert f"({relative_contract.as_posix()})" in docs


def test_documented_core_suite_count_matches_suite_config() -> None:
    docs = _read("docs/benchmarks.md")
    suite = _load_yaml("examples/suites/core.yaml")
    runs = suite["runs"]
    expected_pass = sum(
        1 for run in runs if Path(run["config"]).name.endswith("_safe.yaml")
    )
    expected_fail = len(runs) - expected_pass

    assert f"contains {len(runs)}\nruns" in docs
    assert f"{expected_pass} pass and {expected_fail} fail" in docs


def test_documented_command_snippet_paths_exist_where_practical() -> None:
    markdown_paths = [
        "README.md",
        "docs/demo.md",
        "docs/showcase.md",
        "docs/benchmarks.md",
    ]
    path_flags = {"--registry", "--output", "--baseline", "--save-baseline"}

    for markdown_path in markdown_paths:
        for block in _command_blocks(_read(markdown_path)):
            for line in block.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                tokens = shlex.split(stripped)
                skip_next = False
                for token in tokens:
                    if skip_next:
                        skip_next = False
                        continue
                    if token in path_flags:
                        skip_next = True
                        continue
                    if token.startswith(("docs/", "examples/", "scripts/")):
                        assert Path(token).exists(), (
                            f"{markdown_path} references missing path {token!r}"
                        )


def test_showcase_suite_loads_and_covers_expected_categories() -> None:
    suite = load_suite_config(Path("examples/showcase/showcase.yaml"))

    assert suite.suite_id == "showcase"
    assert len(suite.runs) == 6
    categories = {
        load_config(run.config_path).benchmark.category
        for run in suite.runs
    }
    assert categories == {
        "source_fix",
        "unsafe_command",
        "filesystem_boundary",
        "test_tampering",
        "secret_content",
        "diff_limit",
    }
    assert {run.agent for run in suite.runs} == {"local-command"}


def test_showcase_references_existing_files_and_local_sandbox() -> None:
    for run in load_suite_config(Path("examples/showcase/showcase.yaml")).runs:
        config = load_config(run.config_path)
        assert config.sandbox.type == "local"
        assert config.repo_template is not None
        assert config.repo_template.exists()
        command = config.agent_command
        assert isinstance(command, str)
        argv = shlex.split(command)
        assert argv[0].startswith("python")
        if len(argv) > 1 and argv[1].endswith(".py"):
            assert (config.repo_template / argv[1]).exists()


def test_showcase_summary_sample_is_stable_and_sanitized() -> None:
    summary_path = Path("docs/results/showcase-summary.json")
    markdown_path = Path("docs/results/showcase-summary.md")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    combined = (
        summary_path.read_text(encoding="utf-8")
        + "\n"
        + markdown_path.read_text(encoding="utf-8")
    )

    assert summary["total_scenarios"] == 6
    assert summary["safe_scenarios_allowed"] == 1
    assert summary["unsafe_scenarios_detected"] == 5
    assert summary["scenarios_passed_as_expected"] == 6
    assert set(summary["detection_categories_covered"]) == {
        "unsafe_command",
        "filesystem_boundary",
        "test_tampering",
        "secret_content",
        "diff_limit",
    }
    assert summary["fake_secret_value_rendered"] is False
    assert FAKE_SHOWCASE_SECRET not in combined
    assert not re.search(r"(/Users/|/private/|[A-Za-z]:\\\\)", combined)


def test_showcase_script_help_works() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/showcase_demo.py", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Run the local AgentGuard showcase suite" in result.stdout
