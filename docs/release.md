# Release Process

AgentGuard v0.2.0 was tagged and published as a GitHub release on July 17,
2026. This document describes the version-generic validation and publication
process for a future release. PyPI publishing remains deferred.

## Local Validation

Run from the repository root with the development environment installed:

```bash
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
git diff --check
bash scripts/build_release.sh
bash scripts/package_smoke.sh
.venv/bin/python scripts/showcase_metrics.py --check
.venv/bin/python scripts/adversarial_metrics.py --check
```

`build_release.sh` creates a wheel and source distribution under `dist/`,
checks that the current version is not already tagged at a different commit,
validates package metadata and members, and never publishes artifacts.
`package_smoke.sh` builds and installs the wheel in a disposable virtual
environment outside the source checkout, verifies the installed console entry
point, and runs a non-Docker benchmark using copied repository examples.

Inspect the generated artifacts before a release. Set `VERSION` to the version
already declared in `pyproject.toml` and `agentguard/__init__.py`:

```bash
VERSION=$(.venv/bin/agentguard --version)
unzip -l "dist/agentguard-${VERSION}-py3-none-any.whl"
tar -tzf "dist/agentguard-${VERSION}.tar.gz"
.venv/bin/python scripts/validate_release_artifacts.py \
  "dist/agentguard-${VERSION}-py3-none-any.whl" \
  "dist/agentguard-${VERSION}.tar.gz"
```

The wheel must contain the `agentguard` package, console entry-point metadata,
and the MIT license. The source distribution must additionally contain the
README, project metadata, and license. Repository examples, docs, tests,
workflows, scripts, generated `.agentguard` state, databases, and caches are
not distribution payload.

## CI Expectations

A release pull request should complete these jobs:

- Python 3.9, 3.10, 3.11, and 3.12 non-Docker compatibility tests.
- Ruff and the coverage quality gate on Python 3.11.
- The complete Docker-backed integration suite on Python 3.11.
- Wheel and source-distribution build, content validation, isolated wheel
  installation, installed CLI smoke checks, and artifact upload.

GitHub Actions artifacts are for review only. CI has read-only repository
permissions and no package publishing credentials.

## Release Commands

After the release PR is reviewed, merged, and required CI checks are green,
a maintainer may publish the already-reviewed version:

```bash
git switch main
git pull --ff-only origin main
VERSION=$(.venv/bin/agentguard --version)
bash scripts/build_release.sh
.venv/bin/python scripts/validate_release_artifacts.py \
  "dist/agentguard-${VERSION}-py3-none-any.whl" \
  "dist/agentguard-${VERSION}.tar.gz"
bash scripts/package_smoke.sh
.venv/bin/python scripts/showcase_metrics.py --check
.venv/bin/python scripts/adversarial_metrics.py --check
git tag -a "v${VERSION}" -m "AgentGuard v${VERSION}"
git push origin "v${VERSION}"
```

Prepare release notes from the matching section of `CHANGELOG.md`, then create
the GitHub release from the pushed tag and attach the validated distributions:

```bash
gh release create "v${VERSION}" \
  "dist/agentguard-${VERSION}-py3-none-any.whl" \
  "dist/agentguard-${VERSION}.tar.gz" \
  --title "AgentGuard v${VERSION}" \
  --notes-file "release-notes-v${VERSION}.md"
```

Do not run these commands from a feature branch. Each tag and GitHub release
operation is intentionally a human-approved manual step. No command in this
repository performs those operations automatically.

## Publishing Status

PyPI publishing is intentionally deferred. Before enabling it, choose the PyPI
project ownership and authentication model, add a trusted publishing workflow
with narrowly scoped permissions, and validate against a non-production index.
This repository currently contains no PyPI upload command or credential.
