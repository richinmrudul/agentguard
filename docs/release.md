# Release Process

AgentGuard is the product and repository name. The production PyPI
distribution is `agentguard-evals`, while the import package and console
command remain `agentguard`.

AgentGuard v0.2.1 is a valid published GitHub release, but its Trusted
Publishing run failed before upload because PyPI rejected the original
`agentguard` distribution identity as too similar to another project. Nothing
from v0.2.1 was uploaded to PyPI. Version 0.2.2 is the first intended production
PyPI release under the publishable distribution name `agentguard-evals`.
AgentGuard v0.2.0 and v0.2.1 remain unchanged historical GitHub releases.

## Release Stages

The release stages are deliberately separate:

1. **Validate a release** by testing the reviewed commit, building the wheel
   and source distribution once, inspecting them, and installing the wheel in
   a disposable environment. Validation publishes nothing.
2. **Create the Git tag** `v0.2.2` at the reviewed merge commit. A tag
   identifies source; it does not create a GitHub release or upload a package.
3. **Create the GitHub release** for that existing tag. Publishing the
   non-prerelease release triggers `.github/workflows/publish.yml`.
4. **Approve production PyPI publication** through the protected `pypi`
   GitHub environment. The workflow publishes only the distributions built and
   validated by that workflow run.

## Distribution, Package, And Command Identity

These names intentionally differ:

| Identity | Value |
| --- | --- |
| Product and repository | AgentGuard / `agentguard` |
| PyPI distribution | `agentguard-evals` |
| Python import package | `agentguard` |
| Console command | `agentguard` |

After v0.2.2 is published, users install the distribution but continue to
import and run AgentGuard under its product identity:

```bash
python -m pip install "agentguard-evals==0.2.2"
python -c "import agentguard; print(agentguard.__version__)"
agentguard --version
agentguard --help
```

For an isolated command installation:

```bash
pipx install "agentguard-evals==0.2.2"
agentguard --version
agentguard --help
```

These production installation commands are post-publication instructions.
Until v0.2.2 appears on production PyPI, install from a reviewed source
checkout.

## Why TestPyPI Is Not Used

The relevant AgentGuard namespace on TestPyPI belongs to an unrelated project
and publisher. TestPyPI and production PyPI have independent project ownership,
so that TestPyPI project neither grants nor implies ownership of a production
name. This project must not contact, modify, or use that TestPyPI project.

AgentGuard therefore validates the actual payload without TestPyPI: GitHub
Actions builds the wheel and source distribution once, validates and inspects
those files, installs the wheel in a clean environment, runs the installed CLI
and repository package smoke, and uploads the exact validated distributions as
an inspectable Actions artifact. The production job downloads and publishes
those same files without rebuilding.

## One-Time Trusted Publisher Setup

No PyPI API token, password, repository secret, or other long-lived
publication credential is used. The production PyPI Trusted Publishing flow uses GitHub
OIDC exclusively.

### Production PyPI pending publisher

Configure the pending Trusted Publisher on production PyPI with exactly:

| Field | Value |
| --- | --- |
| PyPI distribution/project | `agentguard-evals` |
| GitHub owner | `richinmrudul` |
| GitHub repository | `agentguard` |
| Workflow filename | `publish.yml` |
| Environment name | `pypi` |

The pending publisher creates the production project only when the trusted
workflow performs the first successful upload. It does not reserve the name
against a race before that upload.

### GitHub environment

The GitHub environment must be named `pypi` and require manual approval for
production publication. Before v0.2.2 is released, change its selected tag
deployment rule from `v0.2.1` to `v0.2.2`. Do not broaden it to arbitrary tags,
branches, or repository administrators, and do not add a PyPI token or
password as an environment or repository secret.

The workflow keeps default permissions at `contents: read`. Only its protected
`publish` job receives `id-token: write`. The OIDC identity is bound to the
repository, workflow filename, and environment configured on PyPI.

## Local Validation

Run from the repository root with the development environment installed:

```bash
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
git diff --check
.venv/bin/python scripts/validate_release_artifacts.py
bash scripts/build_release.sh
bash scripts/package_smoke.sh
.venv/bin/python scripts/showcase_metrics.py --check
.venv/bin/python scripts/adversarial_metrics.py --check
```

`build_release.sh` creates a wheel and source distribution under `dist/` and
validates package metadata and members. Its default ordinary-CI mode does not
assert that `HEAD` is the target of the current version's release tag:
post-release commits are expected, while published tags remain immutable. It
never publishes artifacts.
`package_smoke.sh` normally builds temporary distributions. The publishing
workflow passes its already-built `dist/` directory so the workflow installs
and exercises the exact wheel without rebuilding.

Strict release validation is explicit and must run only on the exact commit
being tagged and published:

```bash
bash scripts/build_release.sh --strict-release-tag
```

That mode requires an annotated `v${VERSION}` tag derived from the package
version and requires the tag to dereference to `HEAD`. The publishing workflow
uses this strict mode in addition to its release-event, distribution-name, and
artifact metadata checks.

Inspect both distributions:

```bash
VERSION=$(.venv/bin/agentguard --version)
unzip -l "dist/agentguard_evals-${VERSION}-py3-none-any.whl"
tar -tzf "dist/agentguard_evals-${VERSION}.tar.gz"
.venv/bin/python scripts/validate_release_artifacts.py \
  "dist/agentguard_evals-${VERSION}-py3-none-any.whl" \
  "dist/agentguard_evals-${VERSION}.tar.gz"
```

The wheel must contain the importable `agentguard` package, `agentguard`
console entry point, and MIT license. The source distribution must additionally
contain the README, project metadata, and license. Repository examples, docs,
tests, workflows, scripts, generated `.agentguard` state, databases, and caches
are not distribution payload.

## Safe v0.2.2 Release Sequence

1. Merge the reviewed release-preparation PR only after all required checks
   pass.
2. Update local `main` with a fast-forward pull and record the exact merge
   commit.
3. Re-run the full validation commands on that commit.
4. Confirm `pyproject.toml`, `agentguard.__version__`, and
   `agentguard --version` all report `0.2.2`; confirm built metadata names the
   distribution `agentguard-evals`.
5. Confirm production PyPI still has no `agentguard-evals` project or `0.2.2`
   release. If the name is occupied, stop before creating a tag or release.
6. Confirm the pending production PyPI Trusted Publisher uses the exact values
   above.
7. Change the protected `pypi` environment tag rule from `v0.2.1` to
   `v0.2.2`, retaining its required reviewer and other protections.
8. Create and push the annotated tag at the reviewed commit:

   ```bash
   git switch main
   git pull --ff-only origin main
   VERSION=$(.venv/bin/agentguard --version)
   test "$VERSION" = "0.2.2"
   git tag -a "v${VERSION}" -m "AgentGuard v${VERSION}"
   git push origin "v${VERSION}"
   ```

9. Prepare release notes from `CHANGELOG.md`, then create a GitHub release for
   the existing `v0.2.2` tag. Do not attach locally rebuilt distributions:

   ```bash
   gh release create "v${VERSION}" \
     --verify-tag \
     --title "AgentGuard v${VERSION}" \
     --notes-file "release-notes-v${VERSION}.md"
   ```

10. Inspect the workflow's build logs, member listings, checksums, installed
    CLI smoke, and `agentguard-evals-v0.2.2-validated-distributions` artifact.
11. Approve the `pypi` deployment only if tag, commit, distribution name,
    version, files, and checksums are correct.
12. After publication, verify the production project and install it from
    production PyPI.

The workflow fails before publication unless the event is a published,
non-prerelease GitHub release, the tag is exactly `v0.2.2`, the checkout is
exactly at that tag, the metadata name is exactly `agentguard-evals`, and all
package versions are exactly `0.2.2`. Pull requests, ordinary pushes, forks,
other tags, workflow dispatches, arbitrary commits, and other releases cannot
enter the publication path.

## Post-Publication Verification

Compare the release tag with both installed metadata and the CLI:

```bash
RELEASE_TAG=$(gh release view v0.2.2 --json tagName --jq .tagName)
python -m venv /tmp/agentguard-release-verify
/tmp/agentguard-release-verify/bin/python -m pip install \
  --no-cache-dir \
  --index-url https://pypi.org/simple \
  "agentguard-evals==0.2.2"
INSTALLED_VERSION=$(
  /tmp/agentguard-release-verify/bin/python -c \
    'from importlib.metadata import version; print(version("agentguard-evals"))'
)
test "$RELEASE_TAG" = "v${INSTALLED_VERSION}"
/tmp/agentguard-release-verify/bin/python -c \
  "import agentguard; print(agentguard.__version__)"
/tmp/agentguard-release-verify/bin/agentguard --version
/tmp/agentguard-release-verify/bin/agentguard --help
```

For pipx:

```bash
pipx install --index-url https://pypi.org/simple "agentguard-evals==0.2.2"
agentguard --version
agentguard --help
```

## Recovery

- **Environment approval rejected or not granted:** no upload occurs. Inspect
  the workflow artifact and logs, correct the concern, and rerun only if
  version `0.2.2` is still absent from PyPI.
- **Publication job fails before upload:** keep the release and tag unchanged,
  diagnose the OIDC publisher/environment configuration, and rerun only after
  confirming PyPI has no files for `0.2.2`.
- **Publication partially succeeds:** do not blindly rerun. Check the PyPI
  release file list and logs. Uploaded filenames cannot be reused, even after
  deletion; prepare a new version if the intended file set cannot be completed.
- **Version already used:** stop. Increment the version through a reviewed
  release PR. Never overwrite an existing version.
- **Tag/version/name mismatch:** do not approve publication. If a GitHub
  release or package publication already exists, use a new version rather than
  moving release history.
- **Production package-name race:** if another party claims
  `agentguard-evals` before first upload, reject deployment and stop. Choose a
  new distribution name through a separate reviewed decision.
- **GitHub release exists but PyPI publication failed:** a GitHub release does
  not prove PyPI availability. Keep public docs explicit and prepare a new
  version if any immutable filename was used.
- **v0.2.1 incident:** preserve the existing v0.2.1 tag, release, and failed
  workflow record. Do not rerun it against the new distribution identity;
  v0.2.2 is the corrective release.

PyPI release files and version filenames are immutable: they cannot be
overwritten. Deleting a file does not make its filename reusable. Any incorrect
or unsafe upload must be corrected with a new package version.
