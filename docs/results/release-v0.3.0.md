# AgentGuard v0.3.0 Release Verification

This versioned record documents the completed v0.3.0 production release. It
preserves the earlier
[`release-candidate-v0.3.0.md`](release-candidate-v0.3.0.md) record unchanged
as pre-release evidence and does not replace historical v0.2.2 evidence.

- Released: 2026-08-11
- Source commit: `f19b54564bdd45fd438f7e48b055c102d2994a04`
- Annotated tag: `v0.3.0`
- Tag object: `3a7671e422ff02e7171741da83b99329e0bcf0aa`
- [GitHub Release](https://github.com/richinmrudul/agentguard/releases/tag/v0.3.0)
- [Production PyPI release](https://pypi.org/project/agentguard-evals/0.3.0/)
- [Trusted Publishing workflow run](https://github.com/richinmrudul/agentguard/actions/runs/31545391719)
- [Build and validation job](https://github.com/richinmrudul/agentguard/actions/runs/31545391719/job/93956650913)
- [Protected publication job](https://github.com/richinmrudul/agentguard/actions/runs/31545391719/job/93956725924)

The annotated tag dereferences exactly to the source commit and has the exact
annotation `AgentGuard v0.3.0`. The GitHub Release is published, non-draft, and
non-prerelease, targets the same commit, and has no manually attached wheel or
source distribution.

## Published Identity

| Identity | Value |
| --- | --- |
| Product | AgentGuard |
| Repository | `richinmrudul/agentguard` |
| PyPI distribution | `agentguard-evals` |
| Python import package | `agentguard` |
| Console command | `agentguard` |
| Version | `0.3.0` |
| Supported Python | 3.9–3.12 |
| Requires-Python | `>=3.9` |

Production PyPI exposes one wheel and one source distribution. The project
metadata does not declare a `Project-URL` mapping, so the PyPI JSON
`project_urls` value is absent rather than inconsistent. No legacy
`agentguard==0.3.0` distribution metadata exists.

## Protected Publication

The release event triggered workflow run `31545391719` at
`refs/tags/v0.3.0` and source commit
`f19b54564bdd45fd438f7e48b055c102d2994a04`. Its build job validated the
release event, ref, version, metadata, archive members, isolated installed
wheel, and package smoke before uploading the exact distributions as Actions
artifact `agentguard-evals-v0.3.0-validated-distributions`.

The publication job waited for required reviewer approval in environment
`pypi`. Approval was granted by the configured reviewer, after which the same
job downloaded artifact ID `9122261829` with archive digest
`sha256:caa8c15e806eff6e25e80b16fb08bc7560051ecd660370e711d5dc692918423b`,
verified `SHA256SUMS`, removed the checksum manifest, and uploaded only the
wheel and source distribution. GitHub deployment `5860189127` ended in
`success`.

The publication used GitHub OIDC Trusted Publishing. No repository or
publication secret was used, the `pypi` environment has no secrets, and no
local artifact, API token, username/password credential, Twine command, or
TestPyPI path was used.

## Artifact Verification

The exact workflow files and the public PyPI downloads were compared by
filename, SHA-256, and bytes and were byte-identical:

| File | Workflow SHA-256 | PyPI SHA-256 | Byte comparison |
| --- | --- | --- | --- |
| `agentguard_evals-0.3.0-py3-none-any.whl` | `446ba25ef9f3eebb2d056606e6493b45ab8d0f4a6431e4d3ecabbfff859e8e26` | `446ba25ef9f3eebb2d056606e6493b45ab8d0f4a6431e4d3ecabbfff859e8e26` | identical |
| `agentguard_evals-0.3.0.tar.gz` | `2c156ff2817b38158dd7fbbf04122ade551b8bda9d4f1cc4a4d59a6ea6182fdf` | `2c156ff2817b38158dd7fbbf04122ade551b8bda9d4f1cc4a4d59a6ea6182fdf` | identical |

Both public archives passed the repository release-artifact validator. They
report `Name: agentguard-evals`, `Version: 0.3.0`, and
`Requires-Python: >=3.9`; retain the `agentguard` import package, console entry
point, MIT license, and packaged JSON Schema; and exclude repository-only
tests, docs, examples, workflows, scripts, caches, local databases, generated
runtime state, secrets, and absolute workspace paths.

## Attestations And Provenance

PyPI exposes a digital publish attestation for each file through its Integrity
API. Each statement names the corresponding artifact and exact SHA-256 digest.
The publisher identity is:

| Field | Value |
| --- | --- |
| Publisher kind | GitHub |
| Repository | `richinmrudul/agentguard` |
| Workflow | `publish.yml` |
| Environment | `pypi` |
| Ref | `refs/tags/v0.3.0` |
| Commit | `f19b54564bdd45fd438f7e48b055c102d2994a04` |

Both attestations include Sigstore certificates and Rekor transparency-log
entries. The publication action generated and uploaded them together with the
corresponding distributions.

## Release Validation

- Local full pytest: 1,401 passed, 15 skipped, one expected duplicate-archive
  warning. All skips were Docker-dependent because the local Docker daemon was
  not running.
- Exact release commit GitHub CI: Python 3.9, 3.10, 3.11, and 3.12 jobs passed;
  Ruff, coverage, artifact validation, isolated install, package smoke, and the
  full Docker-backed Python 3.11 integration job passed.
- Coverage gate: 91.61% statement, 80.88% branch, 89.03% combined against an
  88.00% requirement.
- Focused publishing, release-hardening, initializer, preset, baseline, and PR
  reporting tests: 204 passed.
- Strict MkDocs, workflow YAML parsing, schema generation/parity, 40 maintained
  configuration examples, ordinary and strict release validation, Ruff,
  `git diff --check`, adversarial metrics, and showcase metrics passed.
- Local candidate wheel and source distribution both installed successfully in
  isolated environments. Their hashes were diagnostic only; workflow artifacts
  remained authoritative for publication identity.

## Fresh Production Installation

A new temporary Python 3.9 virtual environment outside the checkout installed
`agentguard-evals==0.3.0` from `https://pypi.org/simple` with pip caching
disabled and `PYTHONPATH` absent.

- Installed metadata resolved as `agentguard-evals==0.3.0` with
  `Requires-Python: >=3.9`.
- `import agentguard` resolved from the temporary environment's
  `site-packages`, and no legacy `agentguard` distribution metadata existed.
- `agentguard --version`, `agentguard --help`, `agentguard presets list`, and
  `agentguard presets show recommended --format json` passed.
- The packaged Draft 2020-12 configuration JSON Schema was accessible and
  valid.
- Python, Node.js, and Go project initialization detected the intended project
  types and commands. All three generated workflows parsed as YAML, retained
  `contents: read`, pinned `agentguard-evals==0.3.0`, and produced
  configurations accepted by the production loader.
- The native Node.js and Go fixture tests passed. The available hosts were
  Node.js 22.18.0 and Go 1.22.12; the Go smoke disabled network access and
  automatic toolchain switching.
- A network-free deterministic `mock-safe` evaluation passed with score
  100/100 and modified only `src/auth_example/login.py`.
- Baseline-aware reporting classified a second run with an available baseline
  as three new and two existing findings while preserving the conservative
  all-blocking-findings gate.

## Historical And Scope Notes

The v0.3.0 source-candidate record and v0.2.2 release evidence were not
rewritten. TestPyPI was not contacted or changed. The v0.2.2 tag, GitHub
Release, production files, and hashes remain unchanged.

Initialization performs bounded inspection and file generation without running
repository tooling or code. AgentGuard CI and its `minimal`, `recommended`, and
`strict` presets perform post-execution validation; they do not contain agent
or test execution. This release does not include an `untrusted-agent` preset or
claim protection against arbitrary hostile code.
