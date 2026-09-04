# AgentGuard v0.3.1 Release Verification

This record documents the completed v0.3.1 production release and preserves
the earlier [`release-candidate-v0.3.1.md`](release-candidate-v0.3.1.md) record
as immutable pre-release evidence.

- Released: 2026-09-04
- Source commit: `99552fed62f649c6474923909d1cdc4ad663b63c`
- Annotated tag: `v0.3.1`
- Tag object: `1272daec254347e257ce4433fdad40a804affdb5`
- Tag annotation: `AgentGuard v0.3.1`
- [GitHub Release](https://github.com/richinmrudul/agentguard/releases/tag/v0.3.1)
- [Production PyPI release](https://pypi.org/project/agentguard-evals/0.3.1/)
- [Trusted Publishing workflow run](https://github.com/richinmrudul/agentguard/actions/runs/33899362820)
- Build and validation job: `101109536622`
- Protected publication job: `101109686928`

The annotated tag dereferences exactly to the source commit. The GitHub
Release is published, non-draft, and non-prerelease. No locally rebuilt
distribution was attached to it or uploaded to PyPI.

## Published Identity

| Identity | Value |
| --- | --- |
| Product | AgentGuard |
| Repository | `richinmrudul/agentguard` |
| PyPI distribution | `agentguard-evals` |
| Python import package | `agentguard` |
| Console command | `agentguard` |
| Version | `0.3.1` |
| Supported Python | 3.9–3.12 |
| Requires-Python | `>=3.9` |

## Protected Publication

Workflow run `33899362820` built and validated the distributions once, then
retained them as artifact ID `9947020366`, named
`agentguard-evals-v0.3.1-validated-distributions`. Its archive digest is
`sha256:cb77e14b3ad0b4791a39fdf158d955dfc5120b6f8eacf41408a1d7790b09d593`.
The protected publication job downloaded those exact files, verified their
checksums, and published without rebuilding. GitHub deployment `6269295276`
ended in `success`.

The `pypi` environment required reviewer `richinmrudul`, prevented
administrator bypass, allowed only tag `v0.3.1`, and contained no publication
secrets. Publication used GitHub OIDC Trusted Publishing, not a token or
password. TestPyPI was not contacted.

## Artifact Verification

The retained workflow distributions and public PyPI downloads were compared
by filename, SHA-256, and bytes:

| File | SHA-256 | Result |
| --- | --- | --- |
| `agentguard_evals-0.3.1-py3-none-any.whl` | `d50a4812c35ebd500072653640391109ee0b5ded119b774407365a8b112b250c` | byte-identical |
| `agentguard_evals-0.3.1.tar.gz` | `d9a7807b22e67e471220f39bc98ca2df0d2e5f94489247fc186194655664469b` | byte-identical |

The deterministic release-toolchain evidence has SHA-256
`bbff8ed37f025c1fe60fc436fe53cf29a5e5bfc2094235437cfcdf19d26386e3`.
Both distributions passed AgentGuard's artifact validator and reported
`agentguard-evals==0.3.1` with `Requires-Python: >=3.9`.

## Validation And Installation

- Local full pytest: 1,839 passed and 16 Docker-dependent tests skipped.
- Coverage: 88.76% combined against the maintained 88% gate.
- Hosted CI passed Python 3.9–3.12, Ruff, coverage, release-artifact checks,
  documentation, and Docker-backed full integration.
- Strict MkDocs, JSON Schema plus 40 maintained examples, adversarial metrics,
  showcase metrics, workflow parsing, ordinary and strict release validation,
  release build, and isolated package smoke passed.
- A fresh no-cache Python 3.9 installation from production PyPI resolved
  `agentguard-evals==0.3.1`, imported `agentguard` from the temporary
  environment, and passed `agentguard --version`, `agentguard --help`, and the
  recommended preset smoke. No legacy `agentguard` distribution was present.

The local Docker daemon was unavailable, so local Docker execution is not
claimed. The exact release candidate passed the hosted Docker integration job.
This record is release-specific evidence, not a claim that every defect or
security weakness has been discovered.
