# Release Candidate Results

Date: 2026-06-14
AgentGuard: 0.1.0
Audited base commit: `ecae57684c7808d5cb1e6953ab963c81b8832c0a`
Candidate source: `release-candidate-hardening` with the Phase 27A fixes
Host: Darwin 24.1.0, arm64, Python 3.9.6

This report consolidates compatible measurements rerun from the current release
candidate. It does not claim production or general agent performance. Raw
generated `.agentguard` artifacts and absolute local paths are not committed.
The sanitized values are also available in
[`release-candidate.json`](release-candidate.json).

## Audit Findings

### Critical

No critical issue was substantiated.

### High

- Primary execution commands returned raw tracebacks and exit `1` for missing
  or unreadable config and suite inputs. They now return an actionable `Error:`
  message and exit `2`.
- Config, suite, profile, and registry YAML accepted duplicate mapping keys.
  A later key could silently replace a policy or command value. These trust
  boundaries now reject duplicate keys with a YAML validation error.

### Medium

- Reports, manifests, baselines, command logs, generated suites, diagnostic
  outputs, and history exports used direct writes. They now use temporary files,
  file sync, and atomic replacement so interruption does not truncate a prior
  artifact.
- Suite, multi-agent benchmark, and CI aggregate IDs used timestamps alone.
  They now include random suffixes, matching run, matrix, checkpoint, and
  diagnostic collision resistance.

### Low

- Package license metadata used deprecated setuptools forms. It now uses the
  SPDX expression `MIT`, an explicit `LICENSE` file, and setuptools 77 or newer.
- The resume demo assumed `.venv/bin/python`. It now accepts
  `AGENTGUARD_PYTHON`, then uses the repository virtual environment when
  available, then falls back to `python3`.

No additional substantiated defect was found in score calculation, Wilson
intervals, sample standard deviation, nearest-rank percentile handling,
baseline/version comparison, checkpoint reconciliation, fail-fast aggregation,
shell invocation, environment allowlisting, secret redaction, symlink
mutation containment, SQLite write locking, deterministic aggregation,
workflow permissions, or archive content.

## Consolidated Metrics

| Area | Current release-candidate result |
|---|---:|
| Benchmark families | 6 |
| Contract scenarios | 12: 6 safe, 6 adversarial |
| Static contracts | 12 passed, 0 failed |
| Full pytest | 467 passed, 15 Docker-gated skipped |
| Statement coverage | 92.00% |
| Branch coverage | 78.99% |
| Combined coverage gate | 89.14% against 88.00% |
| Controlled mutation detection | 20/20, 100.00% |
| Safe-fixture pass rate | 6/6, 100.00% |
| Matrix maximum validated attempts | 250 |
| Matrix best measured speedup | 8.4343x at 8 workers |
| Matrix integrity | PASS |
| Matrix peak traced Python memory | 166,402 bytes |
| Resume attempts reused | 2/4, 50.0% |
| Resume recomputation avoided | 0.565144 seconds |

The full mutation diagnostic covered 10 unsafe and 6 safe controlled
mutations, with no missed, forbidden, or unexpected detections.

The three-trial policy ablation was stable and had a valid 100%/100% control.
Unique controlled detections were Unsafe commands: 1, Scope adherence: 2, and
Diff size: 1. Forbidden paths, Test tampering, and Secret scan remained
redundantly covered for their declared opportunities. These are catalog
contributions, not production effectiveness estimates.

## Machine-Specific Results

The five-iteration overhead study used one warmup and the deterministic
`mock-safe` auth fixture:

| Measure | Median |
|---|---:|
| Direct duration | 0.175482 seconds |
| AgentGuard duration | 0.305518 seconds |
| Absolute overhead | 0.127743 seconds |
| Relative overhead | 73.51% |
| Slowdown ratio | 1.735x |

The fixture is intentionally tiny, so the relative percentage must not be
projected onto external agents, larger repositories, or production workloads.
Matrix timing, speedup, memory, and resume timing are likewise host-specific.

## Compatibility And Packaging

- Declared and CI-tested Python versions: 3.9, 3.10, 3.11, and 3.12.
- Wheel and source distribution built and passed content validation.
- The wheel installed outside the source checkout and passed CLI, registry,
  local-command benchmark, report, and history smoke checks.
- A fresh execution manifest passed hash verification.
- Generated `.agentguard`, coverage, build, distribution, cache, and egg-info
  outputs remain ignored and untracked.
- No tag, release, package upload, PyPI publication, or GitHub release occurred.

Docker was installed but its daemon was not running on the audit host. The 15
Docker-gated tests therefore remain required CI checks and were not weakened.

## Methodology

- [Benchmark contracts](../benchmarks.md)
- [Detection quality](../detection-quality.md)
- [Policy ablation](../policy-ablation.md)
- [Performance diagnostics](../performance.md)
- [Matrix scalability](../scalability.md)
- [Checkpoint resume](../resume.md)
- [Testing and coverage](../testing.md)
- [Release validation](../release.md)

## Recommendation

Ready for release-candidate review, conditional on the required GitHub CI matrix
passing, including Docker integration and Python 3.9-3.12 compatibility. PyPI
publication remains a separate manual decision.
