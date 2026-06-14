# Release Checklist

This checklist governs a release decision after the release-candidate pull
request is reviewed and merged. Completing it does not itself publish anything.

## Required CI Checks

- [ ] Python 3.9 compatibility and non-Docker tests pass.
- [ ] Python 3.10 compatibility and non-Docker tests pass.
- [ ] Python 3.11 compatibility and non-Docker tests pass.
- [ ] Python 3.12 compatibility and non-Docker tests pass.
- [ ] Ruff passes.
- [ ] Coverage quality gate passes at or above 88%.
- [ ] Full Python 3.11 integration job passes with Docker available.
- [ ] Wheel and source distribution build and validate.
- [ ] Installed console entry point works outside the source checkout.
- [ ] Repository-example package smoke passes.

## Artifact Review

- [ ] Inspect wheel and source distribution member lists.
- [ ] Confirm no `.agentguard`, coverage, cache, build, local database, secret,
  test, documentation, example, or workflow artifacts are unintentionally
  packaged.
- [ ] Confirm `LICENSE` is present in wheel and source distribution metadata.
- [ ] Confirm wheel metadata name and version match `pyproject.toml`.
- [ ] Confirm the installed `agentguard --version` and package version agree.
- [ ] Verify release artifacts were produced from the intended reviewed commit.

## Version And Changelog

- [ ] Confirm the version agrees in `pyproject.toml`, `agentguard/__init__.py`,
  CLI output, changelog, and release notes.
- [ ] Confirm the supported Python classifiers remain 3.9 through 3.12.
- [ ] Confirm the SPDX license expression and license file are correct.
- [ ] Review `CHANGELOG.md` for user-visible changes and migration notes.
- [ ] Review the release-candidate metrics without promoting machine-specific
  or synthetic measurements into general claims.

## Security Review

- [ ] Re-run subprocess and `shell=` static searches.
- [ ] Confirm user-controlled commands still execute with `shell=False`.
- [ ] Re-run duplicate-key and malformed YAML regressions.
- [ ] Re-run path traversal and symlink mutation tests.
- [ ] Confirm environment values remain allowlisted and secrets remain redacted
  from commands, reports, manifests, and summaries.
- [ ] Review GitHub workflow permissions and composite-action argv handling.
- [ ] Confirm local-agent documentation still states that host execution is not
  a security boundary.
- [ ] Verify manifests and checkpoint artifact hashes on fresh runs.

## Draft Release Workflow

- [ ] Select the reviewed merge commit; do not release from an unreviewed branch.
- [ ] Re-run the required checks on that exact commit.
- [ ] Build fresh wheel and source distribution in the release environment.
- [ ] Validate and inspect artifacts before any upload.
- [ ] Prepare draft release notes from the changelog and reviewed PRs.
- [ ] Obtain an explicit human publish decision.
- [ ] Create a tag and GitHub release only after that approval.

## Manual Publish Decision

- [ ] Record who approved publication and which commit and artifact hashes were
  approved.
- [ ] Confirm package credentials use least privilege and trusted publishing
  where configured.
- [ ] Confirm the target is correct before upload, including TestPyPI versus
  PyPI.
- [ ] PyPI publication remains separate and manual. CI artifact creation,
  tagging, and GitHub release creation must not implicitly publish to PyPI.

## Rollback And Revocation

- [ ] Record wheel and source distribution SHA-256 hashes.
- [ ] Retain the reviewed commit, CI logs, and artifact inspection record.
- [ ] If a release is defective, stop further publication and mark the affected
  version as yanked where appropriate.
- [ ] Revoke or rotate any credential suspected of exposure.
- [ ] Publish a corrected version rather than replacing an existing artifact.
- [ ] Document the incident, affected versions, remediation, and user action.
