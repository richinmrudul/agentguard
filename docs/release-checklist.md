# Release Checklist

This checklist governs the corrective v0.2.2 release after its preparation
pull request is reviewed and merged. Checking an item does not publish anything.

## Required CI And Local Checks

- [ ] Python 3.9 through 3.12 compatibility and non-Docker tests pass.
- [ ] Ruff and the coverage quality gate pass.
- [ ] Full Python 3.11 integration passes with Docker available.
- [ ] Wheel and source distribution build exactly once in the publish workflow.
- [ ] Artifact metadata and members validate before publication.
- [ ] The exact built wheel installs in a clean environment outside the source
  checkout.
- [ ] Installed `agentguard --version` and `agentguard --help` pass.
- [ ] Repository-example package smoke reuses the already-built distributions.
- [ ] Exact validated distributions are retained as an Actions artifact.

## Identity, Artifact, And Version Review

- [ ] Product and repository remain AgentGuard / `agentguard`.
- [ ] Distribution metadata name is exactly `agentguard-evals`.
- [ ] Python imports remain `agentguard`.
- [ ] Console entry point remains `agentguard`.
- [ ] Wheel is `agentguard_evals-0.2.2-py3-none-any.whl`.
- [ ] Source distribution is `agentguard_evals-0.2.2.tar.gz`.
- [ ] `pyproject.toml`, `agentguard.__version__`, installed
  `agentguard --version`, wheel metadata, and sdist metadata all equal `0.2.2`.
- [ ] No `.agentguard`, coverage, cache, build, local database, secret, test,
  documentation, example, workflow, or script payload is packaged.
- [ ] `LICENSE` is present in wheel and source-distribution metadata.
- [ ] Tag `v0.2.2` points to the reviewed release commit.
- [ ] Workflow artifact checksums match the downloaded files.

## One-Time Publishing Configuration

- [ ] Production PyPI pending publisher uses project `agentguard-evals`, owner
  `richinmrudul`, repository `agentguard`, workflow `publish.yml`, and
  environment `pypi`.
- [ ] GitHub environment `pypi` exists and requires manual approval.
- [ ] Before release, replace its selected tag rule `v0.2.1` with `v0.2.2`.
- [ ] No PyPI token, password, or long-lived publication secret exists.
- [ ] Workflow default permission is `contents: read`.
- [ ] Only the protected publication job has `id-token: write`.
- [ ] Production PyPI still reports `agentguard-evals` and version `0.2.2` as
  unused immediately before the release is created.

## TestPyPI Exclusion

- [ ] Confirm no workflow or release command targets TestPyPI.
- [ ] Remember the relevant TestPyPI namespace belongs to an unrelated
  publisher and must not be used or presented as this project.
- [ ] Use clean installed-wheel smoke and exact artifact inspection instead of
  TestPyPI validation.

## Release And Publication

- [ ] Select the reviewed merge commit and rerun all validation on it.
- [ ] Create and push annotated tag `v0.2.2`; do not create tags automatically.
- [ ] Run `bash scripts/build_release.sh --strict-release-tag` on the exact
  tagged commit before publication; ordinary CI intentionally permits valid
  post-release commits after an immutable tag.
- [ ] Create the GitHub release for the existing tag with `--verify-tag`.
- [ ] Inspect the publish workflow build logs and retained distributions.
- [ ] Confirm the build job succeeded before considering environment approval.
- [ ] Approve `pypi` only when source, tag, metadata name/version, hashes,
  artifact contents, and release notes agree.
- [ ] Confirm the publish job downloads the validated artifact without rebuild.
- [ ] Verify production PyPI, installed distribution version, CLI version, and
  GitHub release tag after publication.

## Failure And Immutability Review

- [ ] Preserve the existing v0.2.1 annotated tag and GitHub release unchanged.
- [ ] Do not rerun the failed v0.2.1 workflow for the new distribution.
- [ ] Record that v0.2.1 was GitHub-only and uploaded nothing to PyPI.
- [ ] Preserve historical v0.1.0 and v0.2.0 release artifacts as historical
  evidence rather than renaming their old filenames.
- [ ] Before rerunning any failed v0.2.2 job, inspect PyPI for partial upload.
- [ ] If a version or filename was used, prepare a new version.
- [ ] If tag, distribution name, or package version differ, do not approve.
- [ ] PyPI files and released filenames cannot be overwritten or reused after
  deletion; corrections require a new version.

## Security And Scope Review

- [ ] Confirm no tag, GitHub release, workflow rerun, or package upload happened
  in the preparation pull request.
- [ ] Confirm no generated distribution, virtual environment, cache, coverage
  output, build directory, or `.agentguard` state is committed.
- [ ] Confirm all third-party Actions use immutable full commit SHAs.
- [ ] Confirm publication is impossible on pull requests, forks, ordinary
  pushes, workflow dispatch, other tags, arbitrary commits, and prereleases.
- [ ] Retain the reviewed commit, workflow logs, artifact SHA-256 hashes, and
  approval record.
