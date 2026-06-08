# Release Process

This document describes release validation for AgentGuard v0.1.0. The current
phase prepares release-ready source and artifacts but does not publish a
package, create a git tag, or create a GitHub release.

## Local Validation

Run from the repository root with the development environment installed:

```bash
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
git diff --check
bash scripts/build_release.sh
bash scripts/package_smoke.sh
```

`build_release.sh` creates a wheel and source distribution under `dist/`,
validates their metadata and members, prints their paths, and never publishes
them. `package_smoke.sh` builds and installs the wheel in a disposable virtual
environment outside the source checkout, verifies the installed console entry
point, and runs a non-Docker benchmark using copied repository examples.

Inspect the generated artifacts before a release:

```bash
unzip -l dist/agentguard-0.1.0-py3-none-any.whl
tar -tzf dist/agentguard-0.1.0.tar.gz
.venv/bin/python scripts/validate_release_artifacts.py \
  dist/agentguard-0.1.0-py3-none-any.whl \
  dist/agentguard-0.1.0.tar.gz
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

## Future Manual Release

After the release-readiness changes are reviewed and merged, a future explicit
release phase should:

1. Confirm the merged commit passes all required CI checks.
2. Replace the v0.1.0 changelog draft marker with the release date and add the
   final comparison link.
3. Re-run local validation from a clean checkout.
4. Create an annotated `v0.1.0` tag at the reviewed commit and push that tag.
5. Create a GitHub release from the tag, using the v0.1.0 changelog section as
   release notes and attaching the validated wheel and source distribution.
6. Verify artifact checksums and installation from the attached wheel.

Each tag and GitHub release operation is intentionally a human-approved manual
step. No command in this repository performs those operations automatically.

## Publishing Status

PyPI publishing is intentionally deferred to a later phase. Before enabling it,
choose the PyPI project ownership and authentication model, add a trusted
publishing workflow with narrowly scoped permissions, and validate the release
against a non-production index. This repository currently contains no PyPI
upload command or publishing credential.
