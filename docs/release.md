# Release Process

AgentGuard is the product and repository name. The production PyPI
distribution is `agentguard-evals`, while the import package and console
command remain `agentguard`.

AgentGuard v0.2.1 is a valid published GitHub release, but its Trusted
Publishing run failed before upload because PyPI rejected the original
`agentguard` distribution identity as too similar to another project. Nothing
from v0.2.1 was uploaded to PyPI. Version 0.2.2 is the first production PyPI
release under the publishable distribution name `agentguard-evals`; it is
available from [PyPI](https://pypi.org/project/agentguard-evals/0.2.2/) and
[GitHub](https://github.com/richinmrudul/agentguard/releases/tag/v0.2.2).
AgentGuard v0.2.0 and v0.2.1 remain unchanged historical GitHub releases.

AgentGuard v0.3.1 is the current production release. It is available from
[PyPI](https://pypi.org/project/agentguard-evals/0.3.1/) and
[GitHub](https://github.com/richinmrudul/agentguard/releases/tag/v0.3.1).
The reviewed source-candidate record remains preserved as historical pre-release
evidence; the completed publication is documented in
[`results/release-v0.3.1.md`](results/release-v0.3.1.md).

## Release Stages

The release stages are deliberately separate:

1. **Validate a release** by testing the reviewed commit, building the wheel
   and source distribution once, inspecting them, and installing the wheel in
   a disposable environment. Validation publishes nothing.
2. **Create the annotated Git tag** for the reviewed version at the exact merge
   commit. A tag identifies source; it does not create a GitHub release or
   upload a package.
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

Users install the distribution but continue to import and run AgentGuard under
its product identity:

```bash
python -m pip install "agentguard-evals==0.3.1"
python -c "import agentguard; print(agentguard.__version__)"
agentguard --version
agentguard --help
```

For an isolated command installation:

```bash
pipx install "agentguard-evals==0.3.1"
agentguard --version
agentguard --help
```

These commands use the released production package. The ordinary package does
not include repository examples; clone the repository for examples, demo
assets, benchmark fixtures, or development work. Docker is required only for
Docker-backed evaluations.

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

## Trusted Publisher Configuration

No PyPI API token, password, repository secret, or other long-lived
publication credential is used. The production PyPI Trusted Publishing flow
uses GitHub OIDC exclusively.

### Production PyPI publisher

The pending publisher configured before v0.2.2 was converted by that successful
first upload into the active production project publisher used by v0.3.1 with
this identity:

| Field | Value |
| --- | --- |
| PyPI distribution/project | `agentguard-evals` |
| GitHub owner | `richinmrudul` |
| GitHub repository | `agentguard` |
| Workflow filename | `publish.yml` |
| Environment name | `pypi` |

Future release operators must verify that this active publisher identity is
still correct before creating a release. Do not replace it with a token-based
publisher.

### GitHub environment

The GitHub environment must be named `pypi` and require manual approval for
production publication. Version 0.3.1 uses a selected-tag deployment rule that
allows only `v0.3.1`. Before each future release, change that rule through a
separately reviewed administrative step to allow only the exact new release
tag. Do not broaden it to arbitrary tags, branches, or repository
administrators, and do not add a PyPI token or password as an environment or
repository secret.

The workflow keeps default permissions at `contents: read`. Only its protected
`publish` job receives `id-token: write`. The OIDC identity is bound to the
repository, workflow filename, and environment configured on PyPI.

## Release Build Toolchain Lock

The authoritative release build installs Python build tooling only from the
reviewed lock at `requirements/release-build-toolchain.txt`. That lock pins the
build frontend, backend, and relevant transitive build dependencies to exact
versions and includes SHA-256 hashes. The publishing workflow and local package
smoke use `--require-hashes` and `--only-binary=:all:` so the build cannot
silently resolve newer tools, accept an unhashed package, or fall back to an
unbounded install immediately before producing distributions.

`scripts/validate_release_toolchain.py` validates the reviewed lock before
installation and verifies the active installed toolchain before building. The
release build emits `dist/release-build-toolchain.json`, an inspectable
artifact containing the lock digest, Python identity, pip identity, every
locked requirement, and the active locked package versions in the build
environment. This evidence covers the authoritative Linux release environment;
it is not a claim of byte-for-byte cross-platform reproducibility.

For a controlled toolchain-lock update, make a reviewed PR that changes only
intentional tool versions and their hashes, regenerates
`requirements/release-build-toolchain.txt` from a clean environment, runs
`scripts/validate_release_toolchain.py`, and records why each toolchain version
changed. Do not broaden exact pins into ranges, remove hashes, add alternate
indexes, or combine an unreviewed lock update with tag, release, or publishing
operations.

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

## Routine Future Release Sequence

1. Prepare a reviewed release PR that updates every authoritative version,
   release note, expected artifact filename, and the publishing workflow's
   exact allowed tag/version. Do not create a tag in that PR.
2. Merge only after all required checks pass, fast-forward local `main`, and
   record the exact merge commit.
3. Re-run the full validation commands on that commit. Confirm
   `pyproject.toml`, `agentguard.__version__`, installed metadata, and
   `agentguard --version` agree; confirm the distribution remains
   `agentguard-evals`.
4. Confirm the proposed version is absent from production PyPI and no tag or
   GitHub release already uses it.
5. Confirm the active production PyPI publisher still uses the exact identity
   above.
6. Change the protected `pypi` environment deployment rule to allow only the
   exact proposed tag, retaining its reviewer and other protections.
7. Create and push the annotated tag at the reviewed commit:

   ```bash
   git switch main
   git pull --ff-only origin main
   VERSION=$(.venv/bin/agentguard --version)
   git tag -a "v${VERSION}" -m "AgentGuard v${VERSION}"
   git push origin "v${VERSION}"
   ```

8. Prepare release notes from `CHANGELOG.md`, then create a GitHub release for
   the existing version tag. Do not attach locally rebuilt distributions:

   ```bash
   gh release create "v${VERSION}" \
     --verify-tag \
     --title "AgentGuard v${VERSION}" \
     --notes-file "release-notes-v${VERSION}.md"
   ```

9. Inspect the workflow's build logs, member listings, checksums, installed
    CLI smoke, and retained validated-distributions artifact.
10. Approve the `pypi` deployment only if tag, commit, distribution name,
    version, files, and checksums are correct.
11. After publication, verify the production project and install it from
    production PyPI.

The workflow fails before publication unless the event is a published,
non-prerelease GitHub release, the tag is exactly `v0.3.1`, the checkout is
exactly at that tag, the metadata name is exactly `agentguard-evals`, and all
package versions are exactly `0.3.1`. Pull requests, ordinary pushes, forks,
other tags, workflow dispatches, arbitrary commits, and other releases cannot
enter the publication path.

## Completed v0.3.1 Publication

The `v0.3.1` release followed the protected path above:

- release commit `99552fed62f649c6474923909d1cdc4ad663b63c`
- annotated tag object `1272daec254347e257ce4433fdad40a804affdb5`
- [GitHub Release](https://github.com/richinmrudul/agentguard/releases/tag/v0.3.1)
- release-triggered workflow run
  [`33899362820`](https://github.com/richinmrudul/agentguard/actions/runs/33899362820)
- manual approval through the protected `pypi` environment
- OIDC Trusted Publishing without a long-lived token or password
- locked release toolchain with retained identity evidence
- exact workflow and public wheel and sdist verified byte-identical
- fresh production-index installation and CLI smoke passed

See the [v0.3.1 release verification record](results/release-v0.3.1.md) for
the authoritative identities, SHA-256 hashes, workflow jobs, and validation.

## Completed v0.3.0 Publication

The `v0.3.0` release followed the protected path above:

- release commit `f19b54564bdd45fd438f7e48b055c102d2994a04`
- annotated tag object `3a7671e422ff02e7171741da83b99329e0bcf0aa`
- [GitHub Release](https://github.com/richinmrudul/agentguard/releases/tag/v0.3.0)
- release-triggered workflow run
  [`31545391719`](https://github.com/richinmrudul/agentguard/actions/runs/31545391719)
- manual approval through the protected `pypi` environment
- OIDC Trusted Publishing without a long-lived token or password
- PyPI digital attestations bound to `richinmrudul/agentguard`, `publish.yml`,
  and environment `pypi`
- exact workflow and public wheel and sdist verified byte-identical
- fresh production-index installation, initializer, mock-agent, and
  baseline-aware reporting smoke checks passed

See the [v0.3.0 release verification record](results/release-v0.3.0.md) for
the authoritative filenames, SHA-256 hashes, workflow jobs, and public-install
results.

## Completed v0.2.2 Publication

The `v0.2.2` release followed the protected path above:

- release commit `dfc06fcbbd05fa924c5d7de861e28d6a9c379653`
- release-triggered workflow run
  [`30400888141`](https://github.com/richinmrudul/agentguard/actions/runs/30400888141)
- manual approval through the `pypi` environment
- OIDC Trusted Publishing without a token or password
- PyPI digital attestations
- exact workflow and public files verified byte-identical

See the [versioned release verification record](results/release-v0.2.2.md) for
test, installation, filename, and SHA-256 evidence.

## Post-Publication Verification

Compare the release tag with both installed metadata and the CLI:

```bash
RELEASE_TAG=$(gh release view v0.3.1 --json tagName --jq .tagName)
python -m venv /tmp/agentguard-release-verify
/tmp/agentguard-release-verify/bin/python -m pip install \
  --no-cache-dir \
  --index-url https://pypi.org/simple \
  "agentguard-evals==0.3.1"
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
pipx install --index-url https://pypi.org/simple "agentguard-evals==0.3.1"
agentguard --version
agentguard --help
```

To compare public files with the exact retained workflow artifacts, download
both into separate empty directories and hash each filename:

```bash
gh run download 33899362820 \
  --name agentguard-evals-v0.3.1-validated-distributions \
  --dir /tmp/agentguard-workflow
python - <<'PY'
import hashlib
import json
import urllib.request
from pathlib import Path

public_dir = Path("/tmp/agentguard-public")
public_dir.mkdir()
with urllib.request.urlopen(
    "https://pypi.org/pypi/agentguard-evals/0.3.1/json"
) as response:
    release = json.load(response)
for file_info in release["urls"]:
    urllib.request.urlretrieve(
        file_info["url"],
        public_dir / file_info["filename"],
    )

for workflow_file in sorted(Path("/tmp/agentguard-workflow").glob("agentguard_evals-*")):
    public_file = public_dir / workflow_file.name
    workflow_hash = hashlib.sha256(workflow_file.read_bytes()).hexdigest()
    public_hash = hashlib.sha256(public_file.read_bytes()).hexdigest()
    print(workflow_file.name, workflow_hash, public_hash)
    assert workflow_hash == public_hash
PY
```

Also inspect the PyPI JSON API for filenames, `Requires-Python`, hashes, and
upload timestamps. PyPI releases are immutable: never treat deletion as a way
to reuse a filename or overwrite a version.

Published PyPI metadata is immutable too. If a packaged README or long
description contains stale release-state prose, do not rewrite, replace,
delete, yank, or republish that version. Correct the source documentation and
release validation so the next package version rejects stale claims before
publication.

## Recovery

- **Environment approval rejected or not granted:** no upload occurs. Inspect
  the workflow artifact and logs, correct the concern, and rerun only if
  the proposed version is still absent from PyPI.
- **Publication job fails before upload:** keep the release and tag unchanged,
  diagnose the OIDC publisher/environment configuration, and rerun only after
  confirming PyPI has no files for the proposed version.
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
PyPI release files and version filenames are immutable: they cannot be
overwritten. Deleting a file does not make its filename reusable. Any incorrect
or unsafe upload must be corrected with a new package version.

## Historical v0.2.1 Publication Incident

Preserve the existing v0.2.1 tag, GitHub release, and failed workflow record.
The build and validation succeeded, but PyPI rejected the unavailable original
distribution identity before upload. Do not rerun v0.2.1 against the
`agentguard-evals` identity; v0.2.2 is the corrective production release.
