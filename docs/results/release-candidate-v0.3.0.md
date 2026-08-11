# AgentGuard v0.3.0 Release Candidate

Status: **source candidate; not published**

This record describes the reviewed v0.3.0 source candidate. It does not claim
that a `v0.3.0` tag, GitHub Release, production PyPI file, or TestPyPI file
exists.

- Candidate version: `0.3.0`
- Candidate commit: the `release-v030-preparation` pull-request head carrying
  this document; the exact immutable commit is recorded by the pull request
  and its checks
- Starting `main`: `f50d660e920f2ef3346de351e249a2b59564ac7c`
- Expected future tag: `v0.3.0`
- Supported Python: 3.9–3.12

## Candidate Identity

| Identity | Value |
| --- | --- |
| Product and repository | AgentGuard / `agentguard` |
| PyPI distribution | `agentguard-evals` |
| Python import package | `agentguard` |
| Console command | `agentguard` |
| Candidate version | `0.3.0` |

Production PyPI continues to serve v0.2.2 until the separately authorized
release process completes. The repository's historical v0.2.2 release evidence
and public links remain unchanged.

## Included Roadmap Work

- safe, conflict-aware `agentguard init` onboarding
- `minimal`, `recommended`, and `strict` post-execution CI policy presets
- packaged Draft 2020-12 configuration JSON Schema and editor integration
- baseline-aware pull-request reporting with bounded summaries and annotations
- conservative Node.js initialization for the exact native `node --test` case
- conservative Go module initialization using the fixed `go test ./...` command

These are statements about implemented and tested behavior, not external
adoption metrics. AgentGuard evaluates observable behavior; it does not claim
universal execution containment or formal security certification.

## Validation Scope

The preparation gate covers version and distribution identity, CLI behavior,
workflow trigger and permission boundaries, schema/loader parity, initializer
output, presets, baseline reporting, full tests and coverage, Ruff, strict
documentation build, deterministic metrics checks, wheel and source archive
metadata and members, isolated artifact installation, and package smoke.

Ordinary release-artifact validation is designed to pass on untagged `main`.
Strict release-tag validation is designed to fail before release because the
annotated `v0.3.0` tag does not yet exist. No temporary tag is used to bypass
that boundary.

## Generated Workflow Boundary

Workflows generated from the v0.3.0 source install
`agentguard-evals==0.3.0`. That exact pin makes the generated output internally
consistent and reproducible after publication, but it is not publicly
installable until production PyPI publication completes. Generated workflows
retain immutable Action SHAs, `contents: read`, pull-request-only triggering,
fork-safe base-SHA handling, and no secrets or write permissions.

## Schema And Package Boundary

The stable canonical v1 schema URL continues to target the checked-in `main`
schema rather than a nonexistent versioned release artifact. The same schema
file is packaged in both distributions and validated against maintained
examples and the production loader. The package remains
`agentguard-evals`; its import and executable remain `agentguard`.

## Expected Release Process

After this preparation is merged and independently inspected, a separately
authorized release operation must update the protected `pypi` environment's
selected-tag rule from `v0.2.2` to exactly `v0.3.0`, preserving manual approval.
Only then may an annotated tag be created and a non-prerelease GitHub Release
be published. The protected workflow builds once, validates tag/ref/version,
reuses checksummed artifacts, and publishes through OIDC only after environment
approval.

## Known Boundaries

- v0.3.0 has not been verified from public PyPI because it is not published.
- Generated v0.3.0 workflow pins cannot resolve publicly before publication.
- Initialization does not execute tooling or repository code, but later tests
  can execute project code and may download dependencies.
- Local-command execution is not a hostile-code containment boundary.
- Enforced contained execution remains deferred; no `untrusted-agent` preset
  is offered.
- No external adoption, timing, or security-effectiveness claim is made here.

## Not Performed During Preparation

- no tag creation or push
- no GitHub Release creation
- no production workflow trigger or environment approval
- no PyPI or TestPyPI upload
- no GitHub environment, secret, branch-protection, Pages, repository, or
  Project visibility change
