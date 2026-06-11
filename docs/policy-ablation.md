# Policy Ablation Study

AgentGuard's policy ablation study asks a narrow research question: within the
versioned controlled mutation catalog, how much required detection behavior is
lost when one policy check is prevented from executing?

```bash
agentguard diagnostics ablation --trials 3 --workers 2
```

This is a controlled synthetic experiment. It does not measure production
security effectiveness, real-world false-positive or false-negative rates, or
the prevalence of policy violations.

## Experiment Design

The study reuses the mutation definitions, fixtures, actions, expectations,
test runner, diff collection, command evidence, check implementations, and
scoring semantics from the
[policy mutation audit](detection-quality.md). It does not duplicate mutation
logic.

1. Apply mutation and category filters before expanding the experiment.
2. Run a control condition with the complete registered check set.
3. Run one condition per studied check with exactly that check omitted from
   check construction and execution.
4. Use a fresh workspace for every condition, mutation, and trial.
5. Preserve control, check-registry, catalog, and trial ordering in results,
   including when workers execute trials concurrently.
6. Convert setup or runtime errors into structured study failures.
7. Recompute result and score from the checks that actually ran.

By default, the study includes policy checks represented by required mutation
detections. The functional `Tests passed` check remains active in every
condition but is not ablated by default. It can be selected explicitly with
`--check tests-passed` when a functional-check comparison is useful.

## Definitions

- **Escaped mutation:** an unsafe mutation with at least one required detection
  in control and no required detection under the ablated condition.
- **Newly passing unsafe mutation:** an unsafe mutation whose scored AgentGuard
  result is `PASS` under ablation but not under control.
- **Unique contribution:** a mutation's required control detection is supplied
  by only one studied check.
- **Redundant coverage:** multiple studied checks supply required control
  detections for the same unsafe mutation.
- **Unstable result:** repeated trials for the same condition and mutation
  disagree on detections, misses, forbidden detections, result, score, or
  runtime outcome.

## Metrics

Control metrics report unsafe and safe mutation counts, controlled expected and
observed detections, controlled mutation detection rate, and safe-fixture pass
rate.

Each disabled-check condition reports escaped mutations, expected detections
lost, detection-rate delta in percentage points, safe-fixture pass-rate delta,
removed failed checks, score delta, newly passing unsafe mutations, and
unchanged unsafe mutations.

Contribution metrics report direct required-detection opportunities, unique
and redundant mutation coverage, and the unique share of direct opportunities.
The overlap matrix counts unsafe mutations detected by each pair of studied
checks in control. Mutation buckets show detection by exactly one, multiple, or
no studied checks.

Score changes use AgentGuard's existing severity deductions. Score is not a
calibrated probability or security confidence.

## Control Validity

The control must satisfy every selected catalog expectation. A missed required
detection, forbidden safe-fixture detection, or runtime failure invalidates the
control. Invalid studies retain raw findings and control failures, but suppress
headline contribution and overlap claims.

The command exits 1 for invalid control, unstable trials, or execution
failures. `--allow-study-failures` preserves those findings while exiting 0.
Invalid catalog, check, filter, trial, worker, or output inputs exit 2 without
an expected traceback.

## Reproduction

Run the complete current catalog:

```bash
agentguard diagnostics ablation \
  --catalog examples/mutations/catalog.yaml \
  --trials 3 \
  --workers 2
```

Select checks and mutations with repeated or comma-separated options:

```bash
agentguard diagnostics ablation \
  --check forbidden-paths,secret-scan \
  --mutation unsafe_add_dotenv,unsafe_add_secret_key
```

Reports are written to:

```text
.agentguard/diagnostics/ablation/<study-id>/ablation.json
.agentguard/diagnostics/ablation/<study-id>/ablation.md
```

Generated `.agentguard/` artifacts are ignored and should not be committed.
A sanitized three-trial result from the current controlled catalog is available
at [`docs/results/policy-ablation-summary.json`](results/policy-ablation-summary.json).

## Interpretation Guidance

Use unique contribution to identify catalog detections that depend on one
check. Use redundant coverage and overlap to see where multiple checks react to
the same controlled evidence. Use escapes and newly passing mutations to
distinguish loss of required detection from a change in overall scored result.

Comparisons are meaningful only for the selected catalog, fixture policies,
check configuration, and AgentGuard revision. A high contribution can indicate
important catalog responsibility, narrow catalog specialization, or both. A
low unique contribution can indicate useful defense in depth rather than an
unnecessary check.

## Limitations

- Synthetic mutations cover selected deterministic evidence patterns.
- Results do not estimate production violation prevalence.
- Controlled detection and safe-fixture rates are not real-world error rates.
- Repeated deterministic trials detect disagreement but do not establish
  statistical significance.
- Pairwise overlap does not prove independence or causal security benefit.
- Results depend on fixture policies, severities, weights, and catalog design.
- Functional test behavior remains part of control scoring even though
  `Tests passed` is excluded from default policy ablation.
