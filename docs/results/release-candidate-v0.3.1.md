# AgentGuard v0.3.1 Release Preparation

Status: **source candidate; not published**

This record describes the reviewed v0.3.1 source candidate. It does not claim
that a `v0.3.1` tag, GitHub Release, production PyPI file, or TestPyPI file
exists.

- Candidate version: `0.3.1`
- Starting `main`: `0fc9cf808820153852e2ca0fd058307076b3253f`
- Expected future tag: `v0.3.1`
- Distribution: `agentguard-evals`
- Import and console command: `agentguard`
- Supported Python: 3.9–3.12

## Scope

This patch release consolidates the completed post-v0.3 quality, defensive
security, and supply-chain hardening tracked by epic #175. It adds no new
product feature. The work covers repository and pack boundaries, process and
Docker lifecycle handling, bounded trace/report processing, portable and
sanitized evidence, standards exports, strict configuration and baseline
validation, generated CI workflows, immutable Action references, and the
locked authoritative release toolchain.

The release does not claim that all security defects have been found or that
Docker or local subprocess execution is an absolute sandbox. Enforced
Enforced contained-agent execution remains separate roadmap work.

## Validation Boundary

The preparation gate covers version and distribution identity, CLI behavior,
workflow trigger and permission boundaries, locked release-toolchain identity,
schema/loader parity, generated workflows, full tests and coverage, Ruff,
strict documentation, deterministic metrics, wheel and source archive metadata
and members, isolated artifact installation, and package smoke.

Ordinary release validation must pass on the untagged preparation commit.
Strict release-tag validation must reject the absent `v0.3.1` tag. The tag is
created only after this preparation is reviewed and merged.

## Publishing Boundary

The protected workflow remains release-only, validates the exact tag, ref,
version, distribution, and artifact names, builds once with the reviewed
hash-locked toolchain, uploads checksummed artifacts, and publishes those exact
files through OIDC from the protected `pypi` environment. TestPyPI is not used.

Before publishing, the selected-tag deployment rule must be changed from
`v0.3.0` to exactly `v0.3.1` while preserving its required reviewer, disabled
admin bypass, and absence of long-lived credentials.

## Historical State

Production PyPI continues to serve v0.3.0 during preparation. Published v0.3.0
metadata and artifacts are immutable and remain unchanged. The packaged README
uses a neutral release-history link during this transition so it neither calls
an older version current nor claims that v0.3.1 is already published.

## Not Performed During Preparation

- no tag creation or push
- no GitHub Release creation
- no production workflow trigger or environment approval
- no PyPI or TestPyPI upload
- no repository setting, environment secret, Pages, protection, milestone, or
  visibility change
