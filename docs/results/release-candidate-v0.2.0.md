# v0.2.0 Release Candidate

Status: **release candidate**
Recommendation: **ready to tag after merge with caveats**

AgentGuard v0.2.0 is ready for a maintainer to tag after this
release-candidate PR merges, assuming required CI remains green. This artifact
is stable and intentionally omits timestamps, hostnames, raw command output,
absolute paths, and package build artifacts.

This PR does not create a tag, GitHub release, PyPI upload, wheel, or source
distribution artifact. v0.2.0 has not been tagged or released yet.

## Version And Package Metadata

- Package: `agentguard` `0.2.0`
- Python: `>=3.9`; tested classifiers for 3.9, 3.10, 3.11, 3.12
- License: `MIT`
- Console script: `agentguard.cli.main:app`
- Runtime dependencies: `PyYAML>=6.0.0`, `typer>=0.12.0`

## Post-v0.1.0 Feature Summary

- adversarial-core benchmark pack foundation
- adversarial benchmark metrics validation
- CI bypass and hidden-instruction adversarial scenarios
- built-in secret detector presets
- filesystem watcher foundation
- filesystem watcher hardening for rename, symlink, rapid-change, and dedup cases
- adversarial secret-detector benchmark coverage
- updated adversarial metrics and pack summaries

## Included In v0.2.0

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

## Package Build And Smoke

- Build: `bash scripts/build_release.sh`
- Validate: `.venv/bin/python scripts/validate_release_artifacts.py dist/agentguard-0.2.0-py3-none-any.whl dist/agentguard-0.2.0.tar.gz`
- Package smoke: `bash scripts/package_smoke.sh`
- Local Phase 41A result: passed before opening the review PR.

## Showcase Metrics

- Scenarios: 6
- Safe scenarios allowed: 1
- Unsafe scenarios detected: 5
- False positives: 0
- False negatives: 0
- Categories: diff_limit, filesystem_boundary, secret_content, test_tampering, unsafe_command

These are curated local-demo metrics, not scientific benchmark results.

## Adversarial Metrics

- Scenarios: 10
- Categories: ci_bypass, dependency_injection, hidden_instruction, prompt_injection, scope_drift, secret_content, secret_exfiltration, test_tampering
- Built-in detector coverage: github-token-shape, npm-token-shape, private-key-header
- Metrics artifact: `docs/results/adversarial-metrics.json`
- Pack summary artifact: `docs/results/adversarial-pack-summary.json`

## Watcher Coverage

- Status: foundation and hardening included
- Modes: auto, polling, disabled

## Known Limitations

- No syscall-level interception is included.
- No privileged OS-native watcher integrations are included.
- No entropy detector or user-provided regex detector is included.
- No hosted dashboard, cloud service, authentication, or account model is included.
- Curated showcase metrics and adversarial metrics are local validation signals, not scientific benchmark results.
- PyPI publishing is deferred and no upload command is included.

## Post-Merge Release Commands

Run these only after this PR merges and the maintainer confirms the target
commit and CI status:

1. `git switch main`
2. `git pull --ff-only origin main`
3. `bash scripts/build_release.sh`
4. `.venv/bin/python scripts/validate_release_artifacts.py dist/agentguard-0.2.0-py3-none-any.whl dist/agentguard-0.2.0.tar.gz`
5. `bash scripts/package_smoke.sh`
6. `git tag -a v0.2.0 -m "AgentGuard v0.2.0"`
7. `git push origin v0.2.0`
8. `gh release create v0.2.0 dist/agentguard-0.2.0-py3-none-any.whl dist/agentguard-0.2.0.tar.gz --title "AgentGuard v0.2.0" --notes-file release-notes-v0.2.0.md`

Prepare `release-notes-v0.2.0.md` from `CHANGELOG.md` before
running the GitHub release command.

## Not Performed By This PR

- git tag creation
- git tag push
- GitHub release creation
- PyPI publication
