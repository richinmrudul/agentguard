import re
import shlex
from pathlib import Path

import yaml


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

    script = demo_script.read_text(encoding="utf-8")
    assert "set -euo pipefail" in script
    assert "--allow-fail-result" in script
    assert "--allow-failures" in script

    assert "docs/demo.md" in readme.read_text(encoding="utf-8")


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
