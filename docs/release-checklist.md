# Release Checklist

This checklist governs v0.2.1 after its preparation pull request is reviewed
and merged. Checking an item does not itself publish anything.

## Required CI And Local Checks

- [ ] Python 3.9 through 3.12 compatibility and non-Docker tests pass.
- [ ] Ruff and the coverage quality gate pass.
- [ ] Full Python 3.11 integration passes with Docker available.
- [ ] Wheel and source distribution build exactly once in the publish workflow.
- [ ] Artifact metadata and members validate before publication.
- [ ] The built wheel installs in a clean environment.
- [ ] Installed `agentguard --version` and `agentguard --help` pass.
- [ ] Repository-example package smoke uses the already-built distributions.
- [ ] The exact validated distributions are retained as an Actions artifact.

## Artifact And Version Review

- [ ] Inspect the wheel and source-distribution member lists.
- [ ] Confirm no `.agentguard`, coverage, cache, build, local database, secret,
  test, documentation, example, or workflow artifacts are packaged.
- [ ] Confirm `LICENSE` is present in wheel and source-distribution metadata.
- [ ] Confirm package metadata name is `agentguard`.
- [ ] Confirm `pyproject.toml`, `agentguard.__version__`, installed
  `agentguard --version`, wheel metadata, and sdist metadata all equal `0.2.1`.
- [ ] Confirm tag `v0.2.1` points to the reviewed release commit.
- [ ] Confirm the workflow artifact checksums match the downloaded files.
- [ ] Review `CHANGELOG.md` and release notes for user-visible changes.

## One-Time Publishing Configuration

- [ ] Production PyPI pending publisher uses owner `richinmrudul`, repository
  `agentguard`, workflow `publish.yml`, environment `pypi`, and distribution
  `agentguard`.
- [ ] The GitHub `pypi` environment exists and requires manual approval.
- [ ] No PyPI token, password, or long-lived publication secret exists in the
  repository, organization, or environment configuration.
- [ ] Workflow default permission is `contents: read`.
- [ ] Only the protected publication job has `id-token: write`.
- [ ] Production PyPI still reports the `agentguard` name and version `0.2.1`
  as unused immediately before the release is created.

## TestPyPI Exclusion

- [ ] Confirm no workflow or release command targets TestPyPI.
- [ ] Remember that TestPyPI's `agentguard` project belongs to an unrelated
  publisher and must not be used or presented as this project.
- [ ] Remember that TestPyPI and production PyPI ownership are independent and
  TestPyPI ownership does not imply production PyPI ownership.
- [ ] Use clean installed-wheel smoke and exact artifact inspection in place of
  TestPyPI validation.

## Release And Publication

- [ ] Select the reviewed merge commit and re-run validation on that commit.
- [ ] Create and push annotated tag `v0.2.1`; do not create tags automatically.
- [ ] Create the GitHub release for the existing tag with `--verify-tag`.
- [ ] Inspect the publish workflow build logs and retained distributions.
- [ ] Confirm the build job succeeded before considering environment approval.
- [ ] Approve the `pypi` environment only when source, tag, metadata, hashes,
  artifact contents, and release notes agree.
- [ ] Confirm the publish job downloads the validated artifact and does not
  rebuild.
- [ ] Verify the production PyPI project, installed version, CLI version, and
  GitHub release tag after publication.

## Failure And Immutability Review

- [ ] A rejected environment approval means nothing was uploaded.
- [ ] Before rerunning a failed job, inspect PyPI to determine whether any file
  was accepted.
- [ ] If the version or filename was already used, prepare a new version.
- [ ] If tag and package version differ, do not approve publication.
- [ ] If the production name is claimed before first upload, stop and make a
  separate distribution-name decision.
- [ ] If the GitHub release exists but PyPI publication failed, do not claim
  PyPI availability.
- [ ] PyPI files and released version filenames cannot be overwritten or
  reused after deletion; corrections require a new version.

## Security And Scope Review

- [ ] Confirm no tag, GitHub release, or package upload happened in the
  preparation pull request.
- [ ] Confirm no generated distribution, virtual environment, cache, coverage
  output, build directory, or `.agentguard` state is committed.
- [ ] Confirm all third-party Actions use immutable full commit SHAs.
- [ ] Confirm release publication is impossible on pull requests, forks,
  ordinary pushes, workflow dispatch, other tags, and arbitrary commits.
- [ ] Retain the reviewed commit, workflow logs, artifact SHA-256 hashes, and
  approval record.
