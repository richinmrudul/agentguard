# Release Process

AgentGuard v0.2.0 was tagged and published as a GitHub release on July 17,
2026. It remains the latest published GitHub release. Version 0.2.1 is prepared
for production PyPI Trusted Publishing, but PyPI publication remains deferred
until the release is approved and performed.

## Release Stages

The release stages are deliberately separate:

1. **Validate a release** by testing the reviewed commit, building the wheel
   and source distribution once, inspecting them, and installing the wheel in
   a disposable environment. Validation does not publish anything.
2. **Create the Git tag** `v0.2.1` at the reviewed merge commit. A tag identifies
   the source but does not create a GitHub release or upload a package.
3. **Create the GitHub release** for that existing tag. Publishing this release
   triggers `.github/workflows/publish.yml`.
4. **Approve production PyPI publication** through the protected `pypi` GitHub
   environment. The workflow publishes only the distributions built and
   validated by that workflow run.

## Why TestPyPI Is Not Used

The `agentguard` namespace on TestPyPI belongs to an unrelated project and
publisher. TestPyPI and production PyPI have independent project ownership, so
that TestPyPI project neither grants nor implies ownership of the production
PyPI name. It also must not be contacted, modified, or used by this project.

AgentGuard therefore does not publish to TestPyPI. The replacement validation
is stricter about the actual payload: GitHub Actions builds the wheel and source
distribution once, validates and inspects those files, installs the wheel in a
clean environment, runs the installed CLI and repository package smoke, and
uploads the exact validated distributions as an inspectable Actions artifact.
The production job downloads and publishes those same files without rebuilding.

The production `agentguard` name is not reserved by this repository merely
because this workflow exists. Its availability must be rechecked immediately
before the first release is created.

## One-Time Trusted Publisher Setup

No PyPI API token, password, repository secret, or other long-lived publication
credential is used. Complete these external settings once:

### Production PyPI pending publisher

While the `agentguard` production project is unclaimed, create a pending Trusted
Publisher on production PyPI with these exact values:

| Field | Value |
| --- | --- |
| PyPI distribution/project | `agentguard` |
| GitHub owner | `richinmrudul` |
| GitHub repository | `agentguard` |
| Workflow filename | `publish.yml` |
| Environment name | `pypi` |

The pending publisher claims the production project only when the trusted
workflow performs the first successful upload. It does not reserve the name
against a race before that upload.

### GitHub environment

Create the GitHub environment named `pypi` and configure required reviewers so
production publication requires manual approval. Limit deployment branches and
tags as tightly as repository settings allow, with `v0.2.1` as the intended
release tag. Do not add a PyPI token or password as an environment or repository
secret.

The workflow keeps default permissions at `contents: read`. Only its `publish`
job receives `id-token: write`, and that job is gated by the `pypi` environment.
The OIDC identity is therefore bound to the repository, workflow filename, and
environment configured on PyPI.

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
and validates package metadata and members. It never publishes artifacts.
`package_smoke.sh` normally builds its own temporary distributions for local
testing. The publishing workflow passes its already-built `dist/` directory,
so that workflow installs and exercises the exact wheel without rebuilding.

Inspect both distributions:

```bash
VERSION=$(.venv/bin/agentguard --version)
unzip -l "dist/agentguard-${VERSION}-py3-none-any.whl"
tar -tzf "dist/agentguard-${VERSION}.tar.gz"
.venv/bin/python scripts/validate_release_artifacts.py \
  "dist/agentguard-${VERSION}-py3-none-any.whl" \
  "dist/agentguard-${VERSION}.tar.gz"
```

The wheel must contain the importable `agentguard` package, console entry-point
metadata, and MIT license. The source distribution must additionally contain
the README, project metadata, and license. Repository examples, docs, tests,
workflows, scripts, generated `.agentguard` state, databases, and caches are
not distribution payload.

## Safe v0.2.1 Release Sequence

1. Merge the reviewed release-preparation PR only after all required checks
   pass.
2. Update local `main` with a fast-forward pull and record the exact merge
   commit.
3. Re-run the full validation commands on that commit.
4. Confirm `pyproject.toml`, `agentguard.__version__`, and
   `agentguard --version` all report `0.2.1`.
5. Confirm production PyPI still has no `agentguard` project or `0.2.1`
   release. If the name is occupied, stop before creating a tag or release.
6. Confirm the pending production PyPI Trusted Publisher and protected `pypi`
   GitHub environment use the exact values above.
7. Create and push the annotated tag at the reviewed commit:

   ```bash
   git switch main
   git pull --ff-only origin main
   VERSION=$(.venv/bin/agentguard --version)
   test "$VERSION" = "0.2.1"
   git tag -a "v${VERSION}" -m "AgentGuard v${VERSION}"
   git push origin "v${VERSION}"
   ```

8. Prepare release notes from `CHANGELOG.md`, then create a GitHub release that
   targets the existing `v0.2.1` tag. Do not attach locally rebuilt
   distributions; the workflow artifact is the publication source:

   ```bash
   gh release create "v${VERSION}" \
     --verify-tag \
     --title "AgentGuard v${VERSION}" \
     --notes-file "release-notes-v${VERSION}.md"
   ```

9. Inspect the workflow's build logs, wheel/sdist member listings, checksums,
   installed CLI smoke, and `agentguard-v0.2.1-validated-distributions`
   artifact.
10. Approve the `pypi` environment deployment only if the tag, commit,
    metadata, files, and checksums are correct.
11. After publication, verify the production project and install it from
    production PyPI.

The workflow fails before publication unless the release event is `published`,
the tag is exactly `v0.2.1`, the checkout is exactly at that tag, and the
project, wheel, and source-distribution versions are exactly `0.2.1`. Pull
requests, ordinary pushes, forks, other tags, arbitrary commits, and workflow
dispatches cannot enter the publication path.

## Post-Publication Verification

Compare the release tag and installed package version:

```bash
RELEASE_TAG=$(gh release view v0.2.1 --json tagName --jq .tagName)
python -m venv /tmp/agentguard-release-verify
/tmp/agentguard-release-verify/bin/python -m pip install \
  --index-url https://pypi.org/simple \
  "agentguard==0.2.1"
INSTALLED_VERSION=$(
  /tmp/agentguard-release-verify/bin/agentguard --version
)
test "$RELEASE_TAG" = "v${INSTALLED_VERSION}"
/tmp/agentguard-release-verify/bin/agentguard --help
```

For an isolated command installation with pipx:

```bash
pipx install --index-url https://pypi.org/simple "agentguard==0.2.1"
agentguard --version
agentguard --help
```

These production installation commands are post-publication verification only;
they are not expected to work while PyPI publication remains deferred.

## Recovery

- **Environment approval rejected or not granted:** no upload occurs. Inspect
  the workflow artifact and logs, correct the approval concern, and rerun the
  failed `publish` job only if version `0.2.1` is still absent from PyPI.
- **Publication job fails before upload:** keep the release and tag unchanged,
  diagnose the OIDC publisher/environment configuration, and rerun only after
  confirming PyPI has no files for `0.2.1`.
- **Publication partially succeeds:** do not blindly rerun. Check the PyPI
  release file list and workflow logs. Uploaded filenames cannot be reused,
  even after deletion; prepare a new version if the intended file set cannot be
  completed safely.
- **Version already used:** stop. Increment the project version, update the
  changelog, review and merge a new release PR, and create a new tag and GitHub
  release. Never overwrite an existing version.
- **Tag/version mismatch:** do not approve publication. If nothing external
  references the bad tag, delete it under the repository's reviewed tag
  correction policy and create the correct tag. If a GitHub release or package
  publication already exists, use a new version instead of moving release
  history.
- **Production package-name race:** if another party claims `agentguard` before
  the first upload, reject the environment deployment and stop. Do not attempt
  to upload to or take over an unrelated project. Choose a new distribution
  name through a separate reviewed design decision.
- **GitHub release exists but PyPI publication failed:** a GitHub release does
  not prove PyPI availability. Keep README and release notes explicit, repair
  the Trusted Publisher/environment configuration, and rerun only if the
  version remains unused. Otherwise prepare a new version.

PyPI release files and version filenames are immutable: they cannot be
overwritten. Deleting a file does not make its filename reusable. Any incorrect
or unsafe upload must be corrected with a new package version.
