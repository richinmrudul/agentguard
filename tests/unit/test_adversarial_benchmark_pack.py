import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

import yaml

from agentguard.benchmarks.contracts import load_benchmark_contract
from agentguard.benchmarks.registry import find_benchmark, load_benchmark_registry
from agentguard.config.loader import load_config
from agentguard.core.suite import load_suite_config
from scripts.adversarial_metrics import build_metrics_report, render_markdown


PACK_PATH = Path("examples/benchmarks/adversarial-core.yaml")
SUMMARY_JSON = Path("docs/results/adversarial-pack-summary.json")
SUMMARY_MD = Path("docs/results/adversarial-pack-summary.md")
METRICS_JSON = Path("docs/results/adversarial-metrics.json")
METRICS_MD = Path("docs/results/adversarial-metrics.md")

REQUIRED_SCENARIO_FIELDS = {
    "id",
    "category",
    "config",
    "repo",
    "contract",
    "description",
    "threat_model",
    "expected_safe_outcome",
    "expected_unsafe_behavior",
    "expected_guards",
    "mode",
    "notes",
}
EXPECTED_CATEGORIES = {
    "prompt_injection",
    "dependency_injection",
    "secret_exfiltration",
    "test_tampering",
    "scope_drift",
}
EXPECTED_GUARDS = {
    "diff_size",
    "forbidden_paths",
    "scope_adherence",
    "secret_scan",
    "test_tampering",
    "unsafe_commands",
}
FORBIDDEN_ARTIFACT_MARKERS = [
    "AGENTGUARD_ADVERSARIAL_FAKE_SECRET",
    "AGENTGUARD_SHOWCASE_SECRET_EXAMPLE",
    "benchmark-secret",
    "diff --git",
    "/Users/",
    "/private/",
    "/tmp/",
    "HOME=",
    "TMPDIR=",
    "javascript:",
    "file:",
]


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _load_pack() -> dict:
    return _load_yaml(PACK_PATH)


def test_adversarial_pack_descriptor_has_required_metadata() -> None:
    pack = _load_pack()

    assert pack["schema"] == "agentguard.adversarial-benchmark-pack"
    assert pack["schema_version"] == 1
    assert pack["pack_id"] == "adversarial-core"
    assert pack["execution"] == {
        "local_first": True,
        "network_required": False,
        "docker_required": False,
        "bounded_runtime": True,
    }
    assert set(pack["categories"]) == EXPECTED_CATEGORIES
    assert set(pack["detection_surfaces"]) == EXPECTED_GUARDS
    assert len(pack["scenarios"]) == 5
    assert pack["limitations"]

    for scenario in pack["scenarios"]:
        assert REQUIRED_SCENARIO_FIELDS <= set(scenario)
        assert scenario["category"] in EXPECTED_CATEGORIES
        assert scenario["description"]
        assert scenario["threat_model"]
        assert scenario["expected_safe_outcome"]
        assert scenario["expected_unsafe_behavior"]
        assert set(scenario["expected_guards"]) <= EXPECTED_GUARDS
        assert set(scenario["mode"]) <= {"post-hoc", "online"}


def test_adversarial_pack_references_existing_registry_configs_repos_and_contracts() -> None:
    pack = _load_pack()
    registry = load_benchmark_registry(Path(pack["registry"]))

    assert Path(pack["suite"]).is_file()
    suite = load_suite_config(Path(pack["suite"]))
    suite_configs = {run.config_path for run in suite.runs}
    assert {run.agent for run in suite.runs} == {"local-command"}

    for scenario in pack["scenarios"]:
        config_path = Path(scenario["config"])
        repo_path = Path(scenario["repo"])
        contract_path = Path(scenario["contract"])

        assert config_path.is_file()
        assert repo_path.is_dir()
        assert contract_path.is_file()
        assert config_path in suite_configs

        config = load_config(config_path)
        assert config.sandbox.type == "local"
        assert config.repo_template == repo_path.resolve()
        assert config.agent_command is not None
        argv = shlex.split(config.agent_command)
        assert argv[0] == "python3"
        if len(argv) > 1 and argv[1].endswith(".py"):
            assert (repo_path / argv[1]).is_file()

        contract = load_benchmark_contract(contract_path)
        assert find_benchmark(registry, contract.benchmark_id) is not None


def test_scope_drift_refactor_is_registered_with_contract() -> None:
    registry = load_benchmark_registry(Path("examples/benchmarks/registry.yaml"))
    entry = find_benchmark(registry, "scope_drift_refactor")

    assert entry is not None
    assert entry.category == "scope_drift"
    assert entry.configs == {
        "safe": Path("examples/configs/scope_drift_refactor_safe.yaml"),
        "adversarial": Path("examples/configs/scope_drift_refactor_overbroad.yaml"),
    }
    assert entry.contract == Path("examples/benchmarks/contracts/scope_drift_refactor.yaml")

    contract = load_benchmark_contract(entry.contract)
    assert contract.benchmark_id == "scope_drift_refactor"
    assert {variant.name for variant in contract.variants} == {"safe", "adversarial"}


def test_adversarial_pack_summary_matches_descriptor() -> None:
    pack = _load_pack()
    summary = json.loads(SUMMARY_JSON.read_text(encoding="utf-8"))
    markdown = SUMMARY_MD.read_text(encoding="utf-8")

    assert summary["schema"] == "agentguard.adversarial-pack-summary"
    assert summary["pack_id"] == pack["pack_id"]
    assert summary["run_command"] == pack["run_command"]
    assert summary["local_first"] is True
    assert summary["network_required"] is False
    assert summary["docker_required"] is False
    assert summary["scenario_count"] == len(pack["scenarios"])
    assert set(summary["categories_covered"]) == set(pack["categories"])
    assert set(summary["detection_surfaces"]) == set(pack["detection_surfaces"])
    assert [item["id"] for item in summary["scenarios"]] == [
        item["id"] for item in pack["scenarios"]
    ]
    assert "agentguard suite examples/suites/adversarial_core.yaml --allow-failures" in markdown


def test_adversarial_metrics_match_descriptor_and_are_fresh() -> None:
    pack = _load_pack()
    metrics = json.loads(METRICS_JSON.read_text(encoding="utf-8"))
    expected = build_metrics_report(metrics_json_path=METRICS_JSON)

    assert metrics == expected
    assert METRICS_MD.read_text(encoding="utf-8") == render_markdown(expected)
    assert metrics["schema"] == "agentguard.adversarial-metrics"
    assert metrics["pack"]["id"] == "adversarial-core"
    assert metrics["validation"]["kind"] == "metadata validation"
    assert metrics["validation"]["runtime_validated"] is False
    assert metrics["coverage"]["total_scenarios"] == len(pack["scenarios"]) == 5
    assert metrics["coverage"]["safe_scenarios"] == 0
    assert metrics["coverage"]["unsafe_scenarios"] == 5
    assert metrics["coverage"]["expected_unsafe_detections"] == 5
    assert set(metrics["coverage"]["categories"]) == EXPECTED_CATEGORIES
    assert set(metrics["coverage"]["detection_surfaces"]) == EXPECTED_GUARDS
    assert metrics["coverage"]["threat_model_count"] == 5
    assert [item["id"] for item in metrics["scenarios"]] == [
        item["id"] for item in pack["scenarios"]
    ]
    for scenario in metrics["scenarios"]:
        assert scenario["threat_model"]
        assert scenario["expected_safe_outcome"]
        assert scenario["expected_unsafe_behavior"]
        assert set(scenario["expected_guards"]) <= EXPECTED_GUARDS


def test_adversarial_metrics_script_check_and_temp_output(tmp_path: Path) -> None:
    check = subprocess.run(
        [sys.executable, "scripts/adversarial_metrics.py", "--check"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert check.returncode == 0
    assert "Adversarial metrics check passed" in check.stdout

    output_dir = tmp_path / "metrics"
    generated = subprocess.run(
        [
            sys.executable,
            "scripts/adversarial_metrics.py",
            "--output-dir",
            str(output_dir),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert generated.returncode == 0
    generated_json = output_dir / "adversarial-metrics.json"
    generated_md = output_dir / "adversarial-metrics.md"
    assert generated_json.is_file()
    assert generated_md.is_file()
    data = json.loads(generated_json.read_text(encoding="utf-8"))
    assert data["metrics_artifacts"] == {
        "json": "adversarial-metrics.json",
        "markdown": "adversarial-metrics.md",
    }
    assert data["coverage"]["total_scenarios"] == 5


def test_adversarial_pack_artifacts_are_sanitized() -> None:
    combined = "\n".join(
        [
            PACK_PATH.read_text(encoding="utf-8"),
            SUMMARY_JSON.read_text(encoding="utf-8"),
            SUMMARY_MD.read_text(encoding="utf-8"),
            METRICS_JSON.read_text(encoding="utf-8"),
            METRICS_MD.read_text(encoding="utf-8"),
        ]
    )

    for marker in FORBIDDEN_ARTIFACT_MARKERS:
        assert marker not in combined
    assert not re.search(r"[A-Za-z]:\\\\", combined)


def test_adversarial_pack_docs_reference_existing_files() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    docs = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in [
            "docs/benchmarks.md",
            "docs/benchmark-packs.md",
            "docs/benchmark-pack-index.md",
            "docs/detection-quality.md",
            "docs/showcase.md",
        ]
    )
    combined = readme + "\n" + docs

    for path in [
        "examples/benchmarks/adversarial-core.yaml",
        "examples/suites/adversarial_core.yaml",
        "docs/results/adversarial-pack-summary.json",
        "docs/results/adversarial-pack-summary.md",
        "docs/results/adversarial-metrics.json",
        "docs/results/adversarial-metrics.md",
    ]:
        assert Path(path).exists()
        assert path in combined
