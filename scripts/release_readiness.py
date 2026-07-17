#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
TARGET_VERSION = "0.2.0"
TARGET_RELEASE = f"v{TARGET_VERSION}"
JSON_OUTPUT = ROOT / "docs/results/release-readiness-v0.2.json"
MARKDOWN_OUTPUT = ROOT / "docs/results/release-readiness-v0.2.md"
RELEASE_CANDIDATE_JSON_OUTPUT = (
    ROOT / "docs/results/release-candidate-v0.2.0.json"
)
RELEASE_CANDIDATE_MARKDOWN_OUTPUT = (
    ROOT / "docs/results/release-candidate-v0.2.0.md"
)
SUPPORTED_PYTHON = ["3.9", "3.10", "3.11", "3.12"]
REQUIRED_DOCS = [
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "docs/release.md",
    "docs/release-checklist.md",
    "docs/demo.md",
    "docs/showcase.md",
    "docs/github-actions.md",
    "docs/static-site.md",
    "docs/detection-quality.md",
    "docs/performance.md",
    "docs/architecture.md",
    "docs/online-guard.md",
]
REQUIRED_EXAMPLES = [
    "examples/showcase/showcase.yaml",
    "examples/github-actions/agentguard-ci.yml",
    "examples/github-actions/agentguard-pr-summary.yml",
    "examples/github-actions/agentguard-showcase.yml",
    "examples/configs/fix_auth_bug_local_command_safe.yaml",
]
REQUIRED_SCRIPTS = [
    "scripts/build_release.sh",
    "scripts/package_smoke.sh",
    "scripts/showcase_demo.sh",
    "scripts/showcase_metrics.py",
    "scripts/validate_release_artifacts.py",
]
CLI_HELP_COMMANDS = [
    ["--help"],
    ["run", "--help"],
    ["suite", "--help"],
    ["matrix", "--help"],
    ["reports", "--help"],
    ["guard", "--help"],
]
POST_MERGE_RELEASE_COMMANDS = [
    "git switch main",
    "git pull --ff-only origin main",
    "bash scripts/build_release.sh",
    ".venv/bin/python scripts/validate_release_artifacts.py "
    f"dist/agentguard-{TARGET_VERSION}-py3-none-any.whl "
    f"dist/agentguard-{TARGET_VERSION}.tar.gz",
    "bash scripts/package_smoke.sh",
    ".venv/bin/python scripts/showcase_metrics.py --check",
    f'git tag -a {TARGET_RELEASE} -m "AgentGuard {TARGET_RELEASE}"',
    f"git push origin {TARGET_RELEASE}",
    f"gh release create {TARGET_RELEASE} "
    f"dist/agentguard-{TARGET_VERSION}-py3-none-any.whl "
    f"dist/agentguard-{TARGET_VERSION}.tar.gz "
    f"--title \"AgentGuard {TARGET_RELEASE}\" "
    f"--notes-file release-notes-{TARGET_RELEASE}.md",
]


def _load_toml(path: Path) -> dict[str, Any]:
    if sys.version_info >= (3, 11):
        import tomllib

        return tomllib.loads(path.read_text(encoding="utf-8"))

    import tomli

    return tomli.loads(path.read_text(encoding="utf-8"))


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise AssertionError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return data


def _check_paths(paths: list[str]) -> list[dict[str, object]]:
    checks = []
    for path in paths:
        exists = (ROOT / path).exists()
        checks.append({"path": path, "exists": exists})
        if not exists:
            raise AssertionError(f"Missing required path: {path}")
    return checks


def _package_metadata() -> dict[str, Any]:
    pyproject = _load_toml(PYPROJECT)
    project = pyproject["project"]
    classifiers = set(project.get("classifiers", []))
    expected_classifiers = {
        f"Programming Language :: Python :: {version}"
        for version in SUPPORTED_PYTHON
    }
    checks = {
        "name": project.get("name") == "agentguard",
        "version": project.get("version") == TARGET_VERSION,
        "description_mentions_local_first": "Local-first"
        in project.get("description", ""),
        "readme": project.get("readme") == "README.md",
        "license": project.get("license") == "MIT",
        "license_files": project.get("license-files") == ["LICENSE"],
        "requires_python": project.get("requires-python") == ">=3.9",
        "python_classifiers": expected_classifiers.issubset(classifiers),
        "console_script": project.get("scripts", {}).get("agentguard")
        == "agentguard.cli.main:app",
        "runtime_dependencies": project.get("dependencies")
        == ["PyYAML>=6.0.0", "typer>=0.12.0"],
        "build_backend": pyproject.get("build-system", {}).get("build-backend")
        == "setuptools.build_meta",
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise AssertionError(f"Package metadata checks failed: {failed}")
    return {
        "name": project["name"],
        "version": project["version"],
        "description": project["description"],
        "requires_python": project["requires-python"],
        "supported_python": SUPPORTED_PYTHON,
        "license": project["license"],
        "console_script": project["scripts"]["agentguard"],
        "runtime_dependencies": project["dependencies"],
        "checks": checks,
    }


def _cli_smoke() -> list[dict[str, object]]:
    results = []
    for arguments in CLI_HELP_COMMANDS:
        completed = subprocess.run(
            [sys.executable, "-m", "agentguard.cli.main", *arguments],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        output = f"{completed.stdout}\n{completed.stderr}"
        passed = completed.returncode == 0 and "Usage:" in output
        results.append(
            {
                "command": "agentguard " + " ".join(arguments),
                "exit_code": completed.returncode,
                "help_rendered": passed,
            }
        )
        if not passed:
            raise AssertionError(f"CLI help failed for: {' '.join(arguments)}")
    version = subprocess.run(
        [sys.executable, "-m", "agentguard.cli.main", "--version"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    passed = version.returncode == 0 and version.stdout.strip() == TARGET_VERSION
    results.append(
        {
            "command": "agentguard --version",
            "exit_code": version.returncode,
            "version_matches_package": passed,
        }
    )
    if not passed:
        raise AssertionError("CLI version smoke failed")
    return results


def _showcase_metrics() -> dict[str, Any]:
    summary = _load_json(ROOT / "docs/results/showcase-summary.json")
    metrics = _load_json(ROOT / "docs/results/showcase-metrics.json")
    detection = metrics["detection_quality"]
    checks = {
        "summary_parseable": summary.get("total_scenarios") == 6,
        "unsafe_detected": detection.get("unsafe_detected") == 5,
        "unsafe_total": detection.get("unsafe_scenarios") == 5,
        "safe_allowed": detection.get("safe_allowed") == 1,
        "false_positives": detection.get("false_positive_count") == 0,
        "false_negatives": detection.get("false_negative_count") == 0,
        "fake_secret_not_rendered": summary.get("fake_secret_value_rendered")
        is False,
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise AssertionError(f"Showcase metric checks failed: {failed}")
    return {
        "summary_artifact": "docs/results/showcase-summary.json",
        "metrics_artifact": "docs/results/showcase-metrics.json",
        "total_scenarios": summary["total_scenarios"],
        "safe_scenarios_allowed": detection["safe_allowed"],
        "unsafe_scenarios_detected": detection["unsafe_detected"],
        "false_positive_count": detection["false_positive_count"],
        "false_negative_count": detection["false_negative_count"],
        "categories": detection["category_coverage"],
        "curated_local_demo_metrics": True,
        "checks": checks,
    }


def _adversarial_metrics() -> dict[str, Any]:
    summary = _load_json(ROOT / "docs/results/adversarial-pack-summary.json")
    metrics = _load_json(ROOT / "docs/results/adversarial-metrics.json")
    coverage = metrics["coverage"]
    detector_coverage = coverage.get("builtin_detector_coverage", [])
    checks = {
        "summary_parseable": summary.get("scenario_count") == 10,
        "metrics_parseable": coverage.get("total_scenarios") == 10,
        "secret_content_category": "secret_content" in coverage.get("categories", []),
        "builtin_detector_coverage": set(detector_coverage)
        == {"github-token-shape", "npm-token-shape", "private-key-header"},
        "fake_secret_values_absent": metrics["sanitization"].get(
            "fake_secret_values_rendered"
        )
        is False,
        "raw_diffs_absent": metrics["sanitization"].get("raw_diffs_included")
        is False,
        "absolute_paths_absent": metrics["sanitization"].get(
            "absolute_workspace_paths_included"
        )
        is False,
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise AssertionError(f"Adversarial metric checks failed: {failed}")
    return {
        "summary_artifact": "docs/results/adversarial-pack-summary.json",
        "metrics_artifact": "docs/results/adversarial-metrics.json",
        "total_scenarios": coverage["total_scenarios"],
        "categories": coverage["categories"],
        "expected_guard_counts": coverage["expected_guard_counts"],
        "builtin_detector_coverage": detector_coverage,
        "validation_modes": coverage["validation_mode_counts"],
        "checks": checks,
    }


def _watcher_coverage() -> dict[str, Any]:
    return {
        "status": "foundation and hardening included",
        "modes": ["auto", "polling", "disabled"],
        "covered_behaviors": [
            "create events",
            "modify events",
            "delete events",
            "rename represented as delete+create in polling mode",
            "symlink create/change/delete events",
            "ignored-path filtering",
            "event deduplication and caps",
        ],
        "limitations": [
            "Polling is not syscall-level containment.",
            "Rapid create-delete activity can be missed between scans.",
            "Privileged OS-native backends remain deferred.",
        ],
        "docs": ["docs/online-guard.md", "docs/architecture.md"],
    }


def build_readiness_summary() -> dict[str, Any]:
    adversarial = _adversarial_metrics()
    return {
        "schema": "agentguard.release-readiness",
        "schema_version": 1,
        "release": TARGET_RELEASE,
        "recommendation": "ready with caveats",
        "scope": "local-first v0.2.0 release readiness; no publishing or tag creation",
        "package_metadata": _package_metadata(),
        "required_docs": _check_paths(REQUIRED_DOCS),
        "required_examples": _check_paths(REQUIRED_EXAMPLES),
        "required_scripts": _check_paths(REQUIRED_SCRIPTS),
        "cli_smoke": _cli_smoke(),
        "showcase_metrics": _showcase_metrics(),
        "adversarial_metrics": adversarial,
        "watcher_coverage": _watcher_coverage(),
        "post_v0_1_feature_summary": [
            "adversarial-core benchmark pack foundation",
            "adversarial benchmark metrics validation",
            "CI bypass and hidden-instruction adversarial scenarios",
            "built-in secret detector presets",
            "filesystem watcher foundation",
            "filesystem watcher hardening for rename, symlink, rapid-change, and dedup cases",
            "adversarial secret-detector benchmark coverage",
            "updated adversarial metrics and pack summaries",
        ],
        "supported_now": [
            "local and Docker-backed benchmark execution",
            "suite and matrix evaluation with JSON and Markdown reports",
            "runtime command and filesystem guard incidents",
            "live diff line enforcement",
            "configured and opt-in built-in secret-content guard and post-hoc scan",
            "guard incident history queries and exports",
            "static HTML report site with incident pages and trend analytics",
            "adversarial-core benchmark pack and metadata metrics",
            "dependency-free polling filesystem watcher mode",
            "GitHub Actions CI gate examples",
            "trace export, verification, replay, and manifests",
            "wheel and source distribution validation without publishing",
        ],
        "deferred_work": [
            "actual v0.2.0 tag or GitHub release",
            "PyPI publishing",
            "hosted dashboard or cloud service",
            "authentication and user accounts",
            "broad adversarial benchmark expansion beyond adversarial-core",
            "privileged OS-native watcher integrations",
            "syscall interception",
            "entropy detectors",
            "user-provided regex detectors",
            "large detector catalog expansion",
        ],
        "validation_summary": {
            "focused_tests": [
                "tests/unit/test_release_validation.py",
                "tests/unit/test_package_smoke.py",
                "tests/unit/test_demo_assets.py",
                "tests/unit/test_adversarial_benchmark_pack.py",
                "tests/unit/test_cli.py",
            ],
            "full_validation_commands": [
                ".venv/bin/python -m pytest",
                ".venv/bin/python -m ruff check .",
                "git diff --check",
                "bash scripts/build_release.sh",
                "bash scripts/package_smoke.sh",
                ".venv/bin/python scripts/showcase_metrics.py --check",
                ".venv/bin/python scripts/adversarial_metrics.py --check",
            ],
            "phase41a_local_result": "passed before opening the review PR",
        },
        "known_limitations": [
            "AgentGuard is local-first and does not claim production sandboxing.",
            "Showcase metrics are curated local-demo metrics, not broad security rates.",
            "Adversarial metrics are metadata validation plus focused smoke coverage, not a broad leaderboard.",
            "Docker-backed coverage depends on Docker availability in CI or locally.",
            "Static reports are snapshots and do not provide live monitoring.",
            "Filesystem watcher coverage is polling-based and not syscall interception.",
            "Publishing remains manual and out of scope for this readiness pass.",
        ],
    }


def build_release_candidate_summary() -> dict[str, Any]:
    readiness = build_readiness_summary()
    metadata = readiness["package_metadata"]
    showcase = readiness["showcase_metrics"]
    adversarial = readiness["adversarial_metrics"]
    return {
        "schema": "agentguard.release-candidate",
        "schema_version": 1,
        "release": TARGET_RELEASE,
        "status": "release candidate",
        "recommendation": "ready to tag after merge with caveats",
        "package_metadata": {
            "name": metadata["name"],
            "version": metadata["version"],
            "requires_python": metadata["requires_python"],
            "supported_python": metadata["supported_python"],
            "license": metadata["license"],
            "console_script": metadata["console_script"],
            "runtime_dependencies": metadata["runtime_dependencies"],
            "checks": metadata["checks"],
        },
        "docs_checklist_status": {
            "changelog_v0_2_0_section": True,
            "release_process_post_merge_commands": True,
            "release_checklist_post_merge_commands": True,
            "readiness_artifact_current": True,
            "release_candidate_artifact_current": True,
        },
        "package_build_validation": {
            "build_command": "bash scripts/build_release.sh",
            "validation_command": (
                ".venv/bin/python scripts/validate_release_artifacts.py "
                f"dist/agentguard-{TARGET_VERSION}-py3-none-any.whl "
                f"dist/agentguard-{TARGET_VERSION}.tar.gz"
            ),
            "wheel": f"dist/agentguard-{TARGET_VERSION}-py3-none-any.whl",
            "sdist": f"dist/agentguard-{TARGET_VERSION}.tar.gz",
            "local_phase41a_result": "passed before opening the review PR",
            "published": False,
        },
        "package_smoke": {
            "command": "bash scripts/package_smoke.sh",
            "local_phase41a_result": "passed before opening the review PR",
            "requires_network_for_temp_venv_dependencies": True,
        },
        "cli_smoke": readiness["cli_smoke"],
        "showcase_metrics": {
            "artifact": showcase["metrics_artifact"],
            "total_scenarios": showcase["total_scenarios"],
            "safe_scenarios_allowed": showcase["safe_scenarios_allowed"],
            "unsafe_scenarios_detected": showcase["unsafe_scenarios_detected"],
            "false_positive_count": showcase["false_positive_count"],
            "false_negative_count": showcase["false_negative_count"],
            "categories": showcase["categories"],
            "curated_local_demo_metrics": True,
        },
        "adversarial_metrics": {
            "artifact": adversarial["metrics_artifact"],
            "summary_artifact": adversarial["summary_artifact"],
            "total_scenarios": adversarial["total_scenarios"],
            "categories": adversarial["categories"],
            "builtin_detector_coverage": adversarial["builtin_detector_coverage"],
        },
        "watcher_coverage": readiness["watcher_coverage"],
        "test_summary": {
            "focused_commands": readiness["validation_summary"]["focused_tests"],
            "full_commands": readiness["validation_summary"][
                "full_validation_commands"
            ],
            "local_phase41a_result": "passed before opening the review PR",
        },
        "post_v0_1_feature_summary": readiness["post_v0_1_feature_summary"],
        "included": readiness["supported_now"],
        "known_limitations": [
            "No syscall-level interception is included.",
            "No privileged OS-native watcher integrations are included.",
            "No entropy detector or user-provided regex detector is included.",
            "No hosted dashboard, cloud service, authentication, or account model is included.",
            "Curated showcase metrics and adversarial metrics are local validation signals, not scientific benchmark results.",
            "PyPI publishing is deferred and no upload command is included.",
        ],
        "post_merge_release_commands": POST_MERGE_RELEASE_COMMANDS,
        "not_performed_by_this_pr": [
            "git tag creation",
            "git tag push",
            "GitHub release creation",
            "PyPI publication",
        ],
    }


def _markdown(summary: dict[str, Any]) -> str:
    metadata = summary["package_metadata"]
    showcase = summary["showcase_metrics"]
    adversarial = summary["adversarial_metrics"]
    validation = summary["validation_summary"]
    features = "\n".join(
        f"- {item}" for item in summary["post_v0_1_feature_summary"]
    )
    supported = "\n".join(f"- {item}" for item in summary["supported_now"])
    deferred = "\n".join(f"- {item}" for item in summary["deferred_work"])
    limitations = "\n".join(f"- {item}" for item in summary["known_limitations"])
    focused = "\n".join(f"- `{item}`" for item in validation["focused_tests"])
    commands = "\n".join(
        f"- `{item}`" for item in validation["full_validation_commands"]
    )
    return f"""# v0.2 Release Readiness

Recommendation: **{summary["recommendation"]}**

AgentGuard {summary["release"]} is ready for release-candidate review as a
local-first safety and reliability evaluation tool, with publishing, hosted
services, and broader production hardening explicitly deferred.

This is a readiness artifact only. v0.2.0 has not been tagged, released on
GitHub, published to PyPI, or otherwise distributed by this PR.

## Package Metadata

- Package: `{metadata["name"]}` `{metadata["version"]}`
- Description: {metadata["description"]}
- Python: `{metadata["requires_python"]}`; tested classifiers for {", ".join(metadata["supported_python"])}
- License: `{metadata["license"]}`
- Console script: `{metadata["console_script"]}`
- Runtime dependencies: {", ".join(f"`{item}`" for item in metadata["runtime_dependencies"])}

## CLI Smoke

The readiness script verifies help rendering for the main CLI and key
subcommands plus `agentguard --version`. It records exit codes and pass/fail
flags in [`release-readiness-v0.2.json`](release-readiness-v0.2.json) without
capturing raw help output.

## Showcase Metrics

- Scenarios: {showcase["total_scenarios"]}
- Safe scenarios allowed: {showcase["safe_scenarios_allowed"]}
- Unsafe scenarios detected: {showcase["unsafe_scenarios_detected"]}
- False positives: {showcase["false_positive_count"]}
- False negatives: {showcase["false_negative_count"]}
- Categories: {", ".join(showcase["categories"])}

These are curated local-demo metrics, not production security rates.

## Adversarial Metrics

- Scenarios: {adversarial["total_scenarios"]}
- Categories: {", ".join(adversarial["categories"])}
- Built-in detector coverage: {", ".join(adversarial["builtin_detector_coverage"])}
- Metrics artifact: `{adversarial["metrics_artifact"]}`
- Pack summary artifact: `{adversarial["summary_artifact"]}`

These metrics validate metadata, expected detection surfaces, and sanitized
coverage artifacts. They are not a benchmark leaderboard.

## Post-v0.1.0 Feature Summary

{features}

## Supported Now

{supported}

## Deferred Work

{deferred}

## Validation Summary

Focused tests:

{focused}

Full validation commands:

{commands}

Phase 41A local result: {validation["phase41a_local_result"]}.

## Known Limitations

{limitations}
"""


def _release_candidate_markdown(summary: dict[str, Any]) -> str:
    metadata = summary["package_metadata"]
    showcase = summary["showcase_metrics"]
    adversarial = summary["adversarial_metrics"]
    features = "\n".join(
        f"- {item}" for item in summary["post_v0_1_feature_summary"]
    )
    included = "\n".join(f"- {item}" for item in summary["included"])
    limitations = "\n".join(f"- {item}" for item in summary["known_limitations"])
    commands = "\n".join(
        f"{index}. `{command}`"
        for index, command in enumerate(
            summary["post_merge_release_commands"],
            start=1,
        )
    )
    not_performed = "\n".join(
        f"- {item}" for item in summary["not_performed_by_this_pr"]
    )
    return f"""# v0.2.0 Release Candidate

Status: **{summary["status"]}**
Recommendation: **{summary["recommendation"]}**

AgentGuard v0.2.0 is ready for a maintainer to tag after this
release-candidate PR merges, assuming required CI remains green. This artifact
is stable and intentionally omits timestamps, hostnames, raw command output,
absolute paths, and package build artifacts.

This PR does not create a tag, GitHub release, PyPI upload, wheel, or source
distribution artifact. v0.2.0 has not been tagged or released yet.

## Version And Package Metadata

- Package: `{metadata["name"]}` `{metadata["version"]}`
- Python: `{metadata["requires_python"]}`; tested classifiers for {", ".join(metadata["supported_python"])}
- License: `{metadata["license"]}`
- Console script: `{metadata["console_script"]}`
- Runtime dependencies: {", ".join(f"`{item}`" for item in metadata["runtime_dependencies"])}

## Post-v0.1.0 Feature Summary

{features}

## Included In v0.2.0

{included}

## Package Build And Smoke

- Build: `{summary["package_build_validation"]["build_command"]}`
- Validate: `{summary["package_build_validation"]["validation_command"]}`
- Package smoke: `{summary["package_smoke"]["command"]}`
- Local Phase 41A result: {summary["package_smoke"]["local_phase41a_result"]}.

## Showcase Metrics

- Scenarios: {showcase["total_scenarios"]}
- Safe scenarios allowed: {showcase["safe_scenarios_allowed"]}
- Unsafe scenarios detected: {showcase["unsafe_scenarios_detected"]}
- False positives: {showcase["false_positive_count"]}
- False negatives: {showcase["false_negative_count"]}
- Categories: {", ".join(showcase["categories"])}

These are curated local-demo metrics, not scientific benchmark results.

## Adversarial Metrics

- Scenarios: {adversarial["total_scenarios"]}
- Categories: {", ".join(adversarial["categories"])}
- Built-in detector coverage: {", ".join(adversarial["builtin_detector_coverage"])}
- Metrics artifact: `{adversarial["artifact"]}`
- Pack summary artifact: `{adversarial["summary_artifact"]}`

## Watcher Coverage

- Status: {summary["watcher_coverage"]["status"]}
- Modes: {", ".join(summary["watcher_coverage"]["modes"])}

## Known Limitations

{limitations}

## Post-Merge Release Commands

Run these only after this PR merges and the maintainer confirms the target
commit and CI status:

{commands}

Prepare `release-notes-v0.2.0.md` from `CHANGELOG.md` before
running the GitHub release command.

## Not Performed By This PR

{not_performed}
"""


def write_readiness_artifacts() -> dict[str, Any]:
    summary = build_readiness_summary()
    JSON_OUTPUT.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    MARKDOWN_OUTPUT.write_text(_markdown(summary), encoding="utf-8")
    release_candidate = build_release_candidate_summary()
    RELEASE_CANDIDATE_JSON_OUTPUT.write_text(
        json.dumps(release_candidate, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    RELEASE_CANDIDATE_MARKDOWN_OUTPUT.write_text(
        _release_candidate_markdown(release_candidate),
        encoding="utf-8",
    )
    return summary


def main() -> int:
    write_readiness_artifacts()
    print("Release readiness artifacts written.")
    print(f"- {JSON_OUTPUT.relative_to(ROOT)}")
    print(f"- {MARKDOWN_OUTPUT.relative_to(ROOT)}")
    print(f"- {RELEASE_CANDIDATE_JSON_OUTPUT.relative_to(ROOT)}")
    print(f"- {RELEASE_CANDIDATE_MARKDOWN_OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
