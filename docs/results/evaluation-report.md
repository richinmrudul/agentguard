# AgentGuard Evaluation Report

Generated: 2026-06-18T00:11:17+00:00
AgentGuard version: 0.1.0
AgentGuard commit: `fdb45bc13e456d212d257c5779abd162ba894951`

This report consolidates existing sanitized AgentGuard result summaries. It does not run external agents, does not read raw `.agentguard/` artifacts by default, and does not claim production security effectiveness.

## Executive Summary

- The benchmark corpus summary is sourced from committed release-candidate data when available.
- Controlled mutation detection rate and safe-fixture pass rate are reported as synthetic, catalog-bound diagnostics.
- Replay metrics are described as replay equivalence on deterministic traces, not agent-behavior replay.
- Coverage gate: 89.14% against 88%.
- Machine-specific timing/scale sections were omitted from the main tables; rerun with `--include-machine-specific` to include them.
- Unavailable inputs: Counterfactual.

## Source Inputs

| Section | Source | SHA-256 | Schema |
|---|---|---|---|
| Ablation | `docs/results/policy-ablation-summary.json` | `8c735f58207f5e72f6d812ef608e8f7cc04d27d3acfa76386662d454ee1f5c4c` | agentguard.policy-ablation-summary |
| Metamorphic | `docs/results/metamorphic-trace-summary.json` | `b8697cb5e7417175c8274cc8e4c3b63c17e8d0203442c0fe56f05cbd8be0838a` | agentguard.metamorphic-trace-summary |
| Release Candidate | `docs/results/release-candidate.json` | `da41003b0bd25b9692fb5e13a619a1a8eb1db3390563db83c65371e09e29aac6` | agentguard.release-candidate-summary |
| Replay | `docs/results/trace-replay-equivalence.json` | `107926d7cc3eb77aab02aebce487b7095b9a1904743b050e408db0fc11a4c4b0` | agentguard.trace-replay-equivalence |
| Resume | `docs/results/resume-summary.json` | `fe121bf92647c214bfd695b853778b33ec41307887aadd05a72a0beefa466286` | agentguard.matrix-resume-summary |
| Scale | `docs/results/matrix-scale-summary.json` | `2970f56202bf8eb211cbef0e126b1acc7b97076d7452e0f1e613554c82702e85` | agentguard.matrix-stress-summary |

## Benchmark Corpus Summary

| Metric | Value |
|---|---:|
| Benchmark families | 6 |
| Scenarios | 12 |
| Safe scenarios | 6 |
| Adversarial scenarios | 6 |
| Static contracts passed | 12 |
| Static contracts failed | 0 |

## CI, Package, And Release Readiness

| Gate | Result |
|---|---|
| Full pytest | 467 passed / 482 collected |
| Docker-gated tests | 15 skipped locally; daemon unavailable locally; Docker integration remains CI-only |
| Python support | 3.9, 3.10, 3.11, 3.12 |
| Wheel built | yes |
| Source distribution built | yes |
| Artifact contents validated | yes |
| Installed wheel smoke passed | yes |
| Manifest verification passed | yes |
| Published | no |

## Coverage Summary

| Metric | Value |
|---|---:|
| Scope | non-Docker and non-package tests |
| Statement coverage | 92% |
| Branch coverage | 78.99% |
| Combined coverage | 89.14% |
| Coverage gate | 88% |
| Gate passed | yes |

## Detection Quality Summary

Synthetic/controlled metric: these catalog-bound values do not imply production security effectiveness.

| Metric | Value |
|---|---:|
| Unsafe mutations | 10 |
| Safe mutations | 6 |
| Expected detections | 20 |
| Observed expected detections | 20 |
| Controlled mutation detection rate | 100% |
| Safe-fixture pass rate | 100% |
| Missed detections | 0 |
| Forbidden detections | 0 |
| Unexpected detections | 0 |

## Policy Ablation Summary

Synthetic/controlled metric: ablation contributions are tied to the mutation catalog and configured policies.

| Check | Direct opportunities | Unique detections | Redundant detections | Contribution |
|---|---:|---:|---:|---:|
| Diff size | 1 | 1 | 0 | 100% |
| Forbidden paths | 4 | 0 | 4 | 0% |
| Scope adherence | 7 | 2 | 5 | 28.57% |
| Secret scan | 4 | 0 | 4 | 0% |
| Test tampering | 2 | 0 | 2 | 0% |
| Unsafe commands | 1 | 1 | 0 | 100% |

## Performance And Overhead Summary

Unavailable in default report: machine-specific overhead is omitted by default. Run `agentguard evaluation report --include-machine-specific --overhead PATH` or use committed defaults with `--include-machine-specific` to include it.

## Scale And Stress Summary

Unavailable in default report: synthetic scheduler speedup is omitted by default. Run `agentguard evaluation report --include-machine-specific --scale PATH` or use committed defaults with `--include-machine-specific` to include it.

## Resume And Recovery Summary

Deterministic local mock matrix checkpoint/resume smoke test.

| Metric | Value |
|---|---:|
| Completed before interruption | 2 |
| Reused attempts | 2 |
| Skipped attempts | 2 |
| Newly executed attempts | 2 |
| Reuse percentage | 50% |
| Artifact verification required | yes |

Unavailable in default report: machine-specific resume timing is omitted by default. Run `agentguard evaluation report --include-machine-specific --resume PATH` or use committed defaults with `--include-machine-specific` to include it.

## Trace, Replay, And Offline Analysis Summary

| Area | Metric | Value |
|---|---|---:|
| Replay | Traces attempted | 12 |
| Replay | Traces replayable | 12 |
| Replay | Exact check equivalence | 12 |
| Replay | Exact score equivalence | 12 |
| Replay | Exact final result equivalence | 12 |
| Replay | Replay equivalence on deterministic traces | 12/12 |
| Metamorphic | Trace count | 2 |
| Metamorphic | Transform applications | 20 |
| Metamorphic | Preserving pass rate | 1 |
| Metamorphic | Changing expected-delta detection rate | 1 |
| Metamorphic | Invalid rejection count | 2 |
| Counterfactual policy comparison | Status | Unavailable |

## Limitations And Threats To Validity

- This is a reporting/consolidation artifact, not a new evaluator.
- Controlled mutation detection rate and safe-fixture pass rate are synthetic diagnostics, not production security rates.
- No real external-agent study is implied unless a future explicit real-agent study summary is provided.
- Replay equivalence applies only to captured deterministic trace evidence and supported policy inputs.
- Timing, throughput, speedup, and memory values are machine-specific when included.
- Ablation source limitation: These are controlled synthetic mutation results, not production security effectiveness.
- Ablation source limitation: Controlled detection and safe-fixture rates are not real-world error rates.
- Ablation source limitation: Repeated deterministic trials do not establish statistical significance.
- Ablation source limitation: Contributions depend on this catalog, its fixtures, and configured policies.
- Metamorphic source limitation: The study uses deterministic local mock traces, not external-agent traces.
- Metamorphic source limitation: No raw transformed traces, absolute paths, command output, file contents, or secrets are included.
- Metamorphic source limitation: Changing transforms are synthetic robustness contracts and do not represent historical agent behavior.
- Metamorphic source limitation: The metrics measure replay/check robustness, not benchmark correctness or policy quality.
- Release Candidate source limitation: Docker was unavailable on the audit host, so Docker integration remains CI-only.
- Release Candidate source limitation: Timing, throughput, speedup, and memory results are machine- and workload-specific.
- Release Candidate source limitation: Controlled mutation and ablation results are synthetic and are not production security rates.
- Release Candidate source limitation: The report identifies the synced main base commit plus the Phase 27A working-tree state because a commit cannot contain its own final hash.
- Replay source limitation: This measures policy replay equivalence, not agent-behavior replay.
- Replay source limitation: Original execution timing is machine-specific.
- Replay source limitation: Local fixture execution is not a Docker containment claim.
- Replay source limitation: Synthetic symlink evidence does not exercise host path traversal.
- Replay source limitation: Exact equivalence applies only to captured, supported policy inputs.
- Resume source limitation: This uses AgentGuard's deterministic local mock workload, not an external coding agent.
- Resume source limitation: Timing is machine-specific and is not an external-agent throughput measurement.
- Resume source limitation: Exactly-once claims apply only to verified logical aggregation and history identity, not external side effects.
- Scale source limitation: This is a synthetic scheduler/report/history workload, not an external-agent benchmark.
- Scale source limitation: Attempts per second are not coding-agent throughput.
- Scale source limitation: Tracemalloc reports traced Python allocations, not total process memory.
- Scale source limitation: Sleep and SQLite overlap can produce measured efficiency above 100%.
- Scale source limitation: Fail-fast time savings are estimates from observed median attempt duration.
- Scale source limitation: Results and saturation are machine- and workload-specific.
- Missing optional sections: Counterfactual.
- Omitted machine-specific sections: Overhead, Resume, Scale.

## Reproduction Commands

These commands reproduce or regenerate the source summaries using documented local workflows; they may update machine-specific metrics.

```bash
PYTHONDONTWRITEBYTECODE=1 scripts/coverage.sh
.venv/bin/python scripts/validate_release_artifacts.py dist/*.whl dist/*.tar.gz
agentguard diagnostics mutations --catalog examples/mutations/catalog.yaml
agentguard diagnostics ablation --catalog examples/mutations/catalog.yaml --trials 3 --workers 3
agentguard diagnostics matrix-stress --attempts 10,50,100,250 --workers 1,2,4,8
agentguard trace replay path/to/trace.jsonl --output-dir .agentguard/replays
agentguard trace metamorphic path/to/traces --output-dir .agentguard/metamorphic
agentguard evaluation report --force
```

See `docs/testing.md`, `docs/detection-quality.md`, `docs/policy-ablation.md`, `docs/scalability.md`, `docs/resume.md`, `docs/replay.md`, and `docs/metamorphic-traces.md` for methodology.
