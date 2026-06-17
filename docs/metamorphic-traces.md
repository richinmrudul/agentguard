# Metamorphic Trace Testing

Metamorphic trace testing stress-tests AgentGuard replay by transforming a
verified execution trace, rebuilding its hash chain, and replaying the
transformed evidence through the real policy checks.

It does not rerun an agent, model, test command, Docker container, network call,
or benchmark workspace.

## Transform Classes

Preserving transforms change replay-irrelevant trace details. Examples include
timestamp variation, check-result display-message variation, and recorded
evidence ordering changes. These should keep recomputed check outcomes, score,
final result, and failed/warning check sets stable.

Changing transforms alter policy-relevant evidence or captured policy inputs.
Examples include adding a modified test file, adding a secret-path file, adding
an unsafe command event, increasing diff totals beyond thresholds, changing the
test exit code, or lowering a policy threshold. These should produce the
expected check outcome in replay or become explicitly non-replayable when
evidence is insufficient.

Invalid transforms intentionally produce internally inconsistent traces, such as
duplicate event sequences, and must be rejected by trace verification.

## Integrity

Transforms operate on typed `ExecutionTrace` models. Valid transformed traces
are serialized only after AgentGuard recomputes event hashes, the final event
hash, the root digest, and the content-derived trace ID. Original trace files
are left unchanged.

Invalid transforms are not repaired. They are written only as generated study
artifacts so verification can prove they are rejected.

## Command

```bash
agentguard trace metamorphic .agentguard/runs/<run-id>/trace.jsonl
agentguard trace metamorphic .agentguard/runs --transform timestamp_variation,add_test_file
```

Options:

- `--transform NAME`: repeatable or comma-separated. Defaults to all built-ins.
- `--trials N`: deterministic trials per transform.
- `--output-dir PATH`: root for generated study reports.
- `--force`: replace an existing study directory.
- `--strict-sources`: require source artifacts for source trace replayability.
- `--allow-robustness-failures`: exit zero while preserving failed findings.

Reports are written under:

```text
.agentguard/replays/metamorphic/<study-id>/metamorphic.json
.agentguard/replays/metamorphic/<study-id>/metamorphic.md
```

Generated transformed traces live under the study directory and remain ignored
with other `.agentguard/` artifacts.

## Metrics

- **Outcome stability rate:** preserving transforms that kept replay outcomes
  stable divided by all preserving cases.
- **Expected-delta detection rate:** changing transforms that produced the
  expected check condition divided by all changing cases.
- **Invalid rejection count:** invalid transformed traces rejected by trace
  verification.
- **Per-check robustness:** pass/fail counts for cases involving each replayed
  check.

## Relation To Other Diagnostics

Mutation testing changes benchmark fixtures or tasks before execution.
Counterfactual replay changes policy snapshots over captured evidence.
Metamorphic trace testing changes the trace evidence itself after execution to
measure replay/check robustness.

## Limitations

Metamorphic testing measures robustness of deterministic replay and policy
checks against controlled trace transformations. It does not prove original
evidence honesty, benchmark correctness, agent identity, or policy quality.
Changing transforms are synthetic and should be interpreted as robustness
contracts, not as historical agent behavior.
