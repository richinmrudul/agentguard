# Deterministic Policy Replay

AgentGuard can replay a verified execution trace through the real policy checks
and scoring pipeline:

```bash
agentguard trace replayability trace.jsonl
agentguard trace replay trace.jsonl
```

Replay reproduces policy evaluation from captured evidence. It does not rerun
or reproduce agent behavior or online filesystem polling. New traces can retain
recorded live line summaries, but replay does not reproduce their detection
timing; post-hoc diff evidence remains the replay input.

## Replay Definition

Replay performs five steps:

1. Verify the trace schema, event ordering, hash chain, and root digest.
2. Reconstruct typed command, test, and file-change evidence.
3. Reconstruct the normalized policy snapshot committed by trace schema v2.
4. Call the same registered check implementations and scorer used by live runs.
5. Compare recomputed checks, evidence, score, and result with recorded events.

Recorded `check_result` events are comparison targets only. Their pass/fail
values never construct recomputed results.

## Policy Snapshot And Evidence

Schema v2 records the enabled check identifiers, resolved severities, scoring
weights, path and command patterns, expected file-count bounds, diff limits,
and command-policy mode. The canonical snapshot hash is part of header
integrity.

Known environment values and secret-like metadata values are never embedded.
If sanitization changes a policy pattern required for exact evaluation, the
trace remains integrity-valid but is explicitly non-replayable.

Replay evidence includes the functional test outcome, normalized changed paths
and line totals, sanitized command and preflight events, and benchmark
metadata. Raw stdout, stderr, repository contents, and unbounded diffs are not
needed by the current checks and remain excluded.

## Replayability

Inspect evidence sufficiency without executing checks:

```bash
agentguard trace replayability trace.jsonl
agentguard trace replayability trace.jsonl --strict-sources
```

Exit codes are `0` for replayable, `1` for valid but non-replayable, and `2`
for malformed, corrupt, or unsupported traces.

Schema v1 remains verifiable but is generally non-replayable because it did not
capture normalized policy inputs. AgentGuard never substitutes current defaults
for missing historical policy. Future unknown check identifiers also make a
trace explicitly non-replayable.

## Replay Reports

By default replay writes:

```text
.agentguard/replays/<replay-id>/replay.json
.agentguard/replays/<replay-id>/replay.md
```

Use `--output-dir PATH` to select another root and `--force` to replace existing
report files. Replay reports include trace identity, schema version, source
status, original and replay AgentGuard versions, policy hash, recorded and
recomputed checks, per-check differences, scores, results, durations, measured
speedup, and confirmation that no external execution occurred.

Replay does not create an ordinary benchmark run. Replay history is deferred:
the current SQLite history model represents agent executions, and recording a
replay there would misleadingly create duplicate run semantics.

## Equivalence

- `exact`: check order, status, severity, score contribution, message, evidence,
  score, result, and failed/warning sets match.
- `semantic`: policy outcomes and score match, but non-policy display text
  differs.
- `divergent`: policy outcome, evidence, scoring, or final result differs.
- `non-replayable`: required evidence or policy inputs are unavailable.

Exact equivalence is required by default. `--allow-divergence` exits zero while
retaining every divergence in the reports. `--no-require-equivalence` also
relaxes the exit requirement.

Replay exits `0` for the required equivalence, `1` for a completed divergent
replay, and `2` for corrupt, unsupported, non-replayable, or output errors.

## Offline Guarantee

The replay path does not invoke an agent, model, test runner, subprocess,
Docker, network client, or copied benchmark workspace. It evaluates only the
verified trace data in memory and writes replay reports.

This is faster than original execution because model and test work is absent.
It is not equivalent to rerunning nondeterministic external behavior.

Metamorphic trace testing builds on this same offline replay path. It applies
deterministic preserving, changing, and invalid transformations to trace models,
recomputes integrity for valid transformed traces, and checks whether replayed
outcomes match the transform contract.

## Integrity And Security Limits

Trace hashes are not signatures. They detect unauthenticated modification but
do not prove who created a trace, agent identity, evidence honesty, policy
completeness, or benchmark correctness. Source verification can detect changed
available artifacts, but detached traces remain replayable without sources
unless `--strict-sources` is requested.

Replay supports the policy captured at execution time. Counterfactual or
alternate-policy analysis is intentionally not implemented yet.

## Equivalence Study

Run the deterministic local study with:

```bash
.venv/bin/python scripts/trace_replay_equivalence.py
```

The sanitized aggregate is committed at
`docs/results/trace-replay-equivalence.json`. It covers safe and adversarial
scenarios for all six registry families, uses temporary local configs rather
than Docker, and records its synthetic symlink limitation explicitly.
