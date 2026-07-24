# v0.2 Release Status

Status: **released**

AgentGuard v0.2.0 was tagged and published as a GitHub release on
July 17, 2026. PyPI publishing, hosted services, and broader production
hardening remain explicitly deferred.

This deterministic artifact records the post-release state. It does not create
or replace tags, releases, or package artifacts.

## Package Metadata

- Package: `agentguard` `0.2.0`
- Current development version: `0.2.1`
- Description: Local-first safety and reliability evaluation framework for AI coding agents.
- Python: `>=3.9`; tested classifiers for 3.9, 3.10, 3.11, 3.12
- License: `MIT`
- Console script: `agentguard.cli.main:app`
- Runtime dependencies: `PyYAML>=6.0.0`, `typer>=0.12.0`

## CLI Smoke

The readiness script verifies help rendering for the main CLI and key
subcommands plus `agentguard --version`. It records exit codes and pass/fail
flags in [`release-readiness-v0.2.json`](release-readiness-v0.2.json) without
capturing raw help output.

## Showcase Metrics

- Scenarios: 6
- Safe scenarios allowed: 1
- Unsafe scenarios detected: 5
- False positives: 0
- False negatives: 0
- Categories: diff_limit, filesystem_boundary, secret_content, test_tampering, unsafe_command

These are curated local-demo metrics, not production security rates.

## Adversarial Metrics

- Scenarios: 10
- Categories: ci_bypass, dependency_injection, hidden_instruction, prompt_injection, scope_drift, secret_content, secret_exfiltration, test_tampering
- Built-in detector coverage: github-token-shape, npm-token-shape, private-key-header
- Metrics artifact: `docs/results/adversarial-metrics.json`
- Pack summary artifact: `docs/results/adversarial-pack-summary.json`

These metrics validate metadata, expected detection surfaces, and sanitized
coverage artifacts. They are not a benchmark leaderboard.

## Post-v0.1.0 Feature Summary

- adversarial-core benchmark pack foundation
- adversarial benchmark metrics validation
- CI bypass and hidden-instruction adversarial scenarios
- built-in secret detector presets
- filesystem watcher foundation
- filesystem watcher hardening for rename, symlink, rapid-change, and dedup cases
- adversarial secret-detector benchmark coverage
- updated adversarial metrics and pack summaries

## Supported Now

- local and Docker-backed benchmark execution
- suite and matrix evaluation with JSON and Markdown reports
- runtime command and filesystem guard incidents
- live diff line enforcement
- configured and opt-in built-in secret-content guard and post-hoc scan
- guard incident history queries and exports
- static HTML report site with incident pages and trend analytics
- adversarial-core benchmark pack and metadata metrics
- dependency-free polling filesystem watcher mode
- GitHub Actions CI gate examples
- trace export, verification, replay, and manifests
- wheel and source distribution validation without publishing

## Deferred Work

- PyPI publishing
- hosted dashboard or cloud service
- authentication and user accounts
- broad adversarial benchmark expansion beyond adversarial-core
- privileged OS-native watcher integrations
- syscall interception
- entropy detectors
- user-provided regex detectors
- large detector catalog expansion

## Validation Summary

Focused tests:

- `tests/unit/test_release_validation.py`
- `tests/unit/test_package_smoke.py`
- `tests/unit/test_demo_assets.py`
- `tests/unit/test_adversarial_benchmark_pack.py`
- `tests/unit/test_cli.py`

Full validation commands:

- `.venv/bin/python -m pytest`
- `.venv/bin/python -m ruff check .`
- `git diff --check`
- `bash scripts/build_release.sh`
- `bash scripts/package_smoke.sh`
- `.venv/bin/python scripts/showcase_metrics.py --check`
- `.venv/bin/python scripts/adversarial_metrics.py --check`

Phase 41A local result: passed before opening the review PR.

## Known Limitations

- AgentGuard is local-first and does not claim production sandboxing.
- Showcase metrics are curated local-demo metrics, not broad security rates.
- Adversarial metrics are metadata validation plus focused smoke coverage, not a broad leaderboard.
- Docker-backed coverage depends on Docker availability in CI or locally.
- Static reports are snapshots and do not provide live monitoring.
- Filesystem watcher coverage is polling-based and not syscall interception.
- PyPI publishing remains deferred.
