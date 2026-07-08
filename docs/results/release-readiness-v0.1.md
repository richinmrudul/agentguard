# v0.1 Release Readiness

Recommendation: **ready with caveats**

AgentGuard v0.1.0 is ready for release-candidate review as a
local-first safety and reliability evaluation tool, with publishing, hosted
services, and broader production hardening explicitly deferred.

## Package Metadata

- Package: `agentguard` `0.1.0`
- Description: Local-first safety and reliability evaluation framework for AI coding agents.
- Python: `>=3.9`; tested classifiers for 3.9, 3.10, 3.11, 3.12
- License: `MIT`
- Console script: `agentguard.cli.main:app`
- Runtime dependencies: `PyYAML>=6.0.0`, `typer>=0.12.0`

## CLI Smoke

The readiness script verifies help rendering for the main CLI and key
subcommands plus `agentguard --version`. It records exit codes and pass/fail
flags in [`release-readiness-v0.1.json`](release-readiness-v0.1.json) without
capturing raw help output.

## Showcase Metrics

- Scenarios: 6
- Safe scenarios allowed: 1
- Unsafe scenarios detected: 5
- False positives: 0
- False negatives: 0
- Categories: diff_limit, filesystem_boundary, secret_content, test_tampering, unsafe_command

These are curated local-demo metrics, not production security rates.

## Supported Now

- local and Docker-backed benchmark execution
- suite and matrix evaluation with JSON and Markdown reports
- runtime command and filesystem guard incidents
- live diff line enforcement
- configured secret-content guard and post-hoc secret-content scan
- guard incident history queries and exports
- static HTML report site with incident pages and trend analytics
- GitHub Actions CI gate examples
- trace export, verification, replay, and manifests
- wheel and source distribution validation without publishing

## Deferred Work

- actual v0.1 tag or GitHub release
- PyPI publishing
- hosted dashboard or cloud service
- authentication and user accounts
- broad adversarial benchmark expansion
- native filesystem watchers
- syscall interception
- regex, entropy, or built-in secret detectors

## Validation Summary

Focused tests:

- `tests/unit/test_release_validation.py`
- `tests/unit/test_package_smoke.py`
- `tests/unit/test_demo_assets.py`
- `tests/unit/test_cli.py`
- `tests/unit/test_action_metadata.py`

Full validation commands:

- `.venv/bin/python -m pytest`
- `.venv/bin/python -m ruff check .`
- `git diff --check`
- `.venv/bin/python scripts/validate_release_artifacts.py dist/agentguard-0.1.0-py3-none-any.whl dist/agentguard-0.1.0.tar.gz`
- `bash scripts/package_smoke.sh`
- `.venv/bin/python scripts/showcase_metrics.py`

Phase 36A local result: passed before opening the review PR.

## Known Limitations

- AgentGuard is local-first and does not claim production sandboxing.
- Showcase metrics are curated local-demo metrics, not broad security rates.
- Docker-backed coverage depends on Docker availability in CI or locally.
- Static reports are snapshots and do not provide live monitoring.
- Publishing remains manual and out of scope for this readiness pass.
