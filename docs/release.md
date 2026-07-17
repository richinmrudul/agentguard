# Release Process

This document describes release validation for AgentGuard v0.2.0. AgentGuard
v0.1.0 has already been released; the current release-readiness phase prepares
v0.2.0 review artifacts but does not publish a package, create a git tag, or
create a GitHub release.

## Local Validation

Run from the repository root with the development environment installed:

```bash
.venv/bin/python scripts/release_readiness.py
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
git diff --check
bash scripts/build_release.sh
bash scripts/package_smoke.sh
.venv/bin/python scripts/showcase_metrics.py --check
```

`release_readiness.py` validates package metadata, required docs and examples,
CLI help rendering, committed showcase metrics, adversarial metrics, watcher
coverage notes, and supported/deferred scope. It writes the stable review
artifacts `docs/results/release-readiness-v0.2.json` and
`docs/results/release-readiness-v0.2.md`, plus
`docs/results/release-candidate-v0.2.0.json` and
`docs/results/release-candidate-v0.2.0.md`, without timestamps, hostnames, raw
command output, absolute paths, or secret values.

`build_release.sh` creates a wheel and source distribution under `dist/`,
validates their metadata and members, prints their paths, and never publishes
them. `package_smoke.sh` builds and installs the wheel in a disposable virtual
environment outside the source checkout, verifies the installed console entry
point, and runs a non-Docker benchmark using copied repository examples.
`showcase_metrics.py --check` validates committed stable showcase metrics
without rewriting timing-sensitive local overhead artifacts.

Inspect the generated artifacts before a release:

```bash
unzip -l dist/agentguard-0.2.0-py3-none-any.whl
tar -tzf dist/agentguard-0.2.0.tar.gz
.venv/bin/python scripts/validate_release_artifacts.py \
  dist/agentguard-0.2.0-py3-none-any.whl \
  dist/agentguard-0.2.0.tar.gz
```

The wheel must contain the `agentguard` package, console entry-point metadata,
and the MIT license. The source distribution must additionally contain the
README, project metadata, and license. Repository examples, docs, tests,
workflows, scripts, generated `.agentguard` state, databases, and caches are
not distribution payload.

## CI Expectations

A release-readiness pull request should complete these jobs:

- Python 3.9, 3.10, 3.11, and 3.12 non-Docker compatibility tests.
- Ruff on Python 3.11.
- The complete Docker-backed integration suite on Python 3.11.
- Wheel and source-distribution build, content validation, isolated wheel
  installation, installed CLI smoke checks, and artifact upload.

GitHub Actions artifacts are for review only. CI has read-only repository
permissions and no package publishing credentials.

## Post-Merge Release Commands

After the release-candidate PR is reviewed, merged, and required CI checks are
green, a maintainer can cut v0.2.0 with these manual commands:

```bash
git switch main
git pull --ff-only origin main
bash scripts/build_release.sh
.venv/bin/python scripts/validate_release_artifacts.py \
  dist/agentguard-0.2.0-py3-none-any.whl \
  dist/agentguard-0.2.0.tar.gz
bash scripts/package_smoke.sh
.venv/bin/python scripts/showcase_metrics.py --check
git tag -a v0.2.0 -m "AgentGuard v0.2.0"
git push origin v0.2.0
```

Prepare release notes from the v0.2.0 section of `CHANGELOG.md`, then create a
GitHub release from the pushed tag and attach the validated wheel and source
distribution:

```bash
gh release create v0.2.0 \
  dist/agentguard-0.2.0-py3-none-any.whl \
  dist/agentguard-0.2.0.tar.gz \
  --title "AgentGuard v0.2.0" \
  --notes-file release-notes-v0.2.0.md
```

Do not run these commands from a feature branch. Each tag and GitHub release
operation is intentionally a human-approved manual step. No command in this
repository performs those operations automatically.

## Publishing Status

PyPI publishing is intentionally deferred to a later phase. Before enabling it,
choose the PyPI project ownership and authentication model, add a trusted
publishing workflow with narrowly scoped permissions, and validate the release
against a non-production index. This repository currently contains no PyPI
upload command or publishing credential.
