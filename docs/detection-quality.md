# Detection Quality Diagnostics

AgentGuard's policy mutation audit measures how the configured checks respond
to a versioned set of controlled safe and unsafe repository mutations:

```bash
agentguard diagnostics mutations
```

The audit is deterministic, local, non-Docker, and network-free. It executes no
external model or paid API.

For the faster recruiter-oriented proof layer, the showcase metrics report
summarizes the curated demo scenarios:

```bash
.venv/bin/python scripts/showcase_metrics.py
```

The committed sample at
[`docs/results/showcase-metrics.json`](results/showcase-metrics.json) reports
5/5 unsafe showcase scenarios detected, 1/1 safe showcase scenario allowed, 0
false positives, and 0 false negatives. Those metrics are scoped to the
curated showcase pack; the mutation audit below remains the broader controlled
check-quality diagnostic.

For post-v0.1 adversarial evaluation coverage, the `adversarial-core` pack
groups ten deterministic local unsafe scenarios across prompt injection,
dependency/script injection, secret-path exfiltration behavior, CI bypass,
hidden-instruction following, built-in secret detector validation, test
tampering, and scope drift:

```bash
agentguard suite examples/suites/adversarial_core.yaml --allow-failures
```

The committed summary at
[`docs/results/adversarial-pack-summary.json`](results/adversarial-pack-summary.json)
lists the scenarios, expected detection surfaces, run command, and limitations.
It is a static coverage summary, not volatile run output or a production
quality metric.

Generate and verify the stable adversarial metadata metrics with:

```bash
.venv/bin/python scripts/adversarial_metrics.py
.venv/bin/python scripts/adversarial_metrics.py --check
```

The metrics artifacts at
[`docs/results/adversarial-metrics.json`](results/adversarial-metrics.json) and
[`docs/results/adversarial-metrics.md`](results/adversarial-metrics.md)
answer how many adversarial scenarios exist, which categories and threat
models are covered, which built-in detector IDs are represented, and which
guard/check surfaces are expected to catch them. They are metadata validation.
Runtime detection is validated separately by running the local adversarial
suite, so committed metrics do not contain raw
diffs, command logs, generated `.agentguard` paths, or machine-specific output.

## Methodology

The versioned catalog at
[`examples/mutations/catalog.yaml`](../examples/mutations/catalog.yaml)
defines ordered mutations with:

- a stable ID, description, class, and category
- an existing repository fixture and local AgentGuard config
- one action from a closed, data-only action set
- expected failed checks
- forbidden failed checks

For every selected mutation, AgentGuard copies the source fixture into a fresh
isolated workspace, creates a git baseline, applies the deterministic action,
runs the configured tests, collects the real git diff and command events, and
executes the ordinary check and scoring pipeline. The source fixture and caller
repository are never modified.

Actions can write, replace, append bounded generated lines, or delete files;
record one of the predefined benign or blocked-unsafe command events; compose
those actions; or write through an existing in-workspace symlink. Catalog YAML
cannot provide arbitrary shell commands. Absolute paths, parent traversal,
unknown actions, and symlink targets outside the isolated workspace are
rejected.

Runtime or setup errors become structured failed mutation results so the report
remains inspectable.

## Catalog Scope

The initial catalog contains 16 mutations:

- 10 unsafe mutations covering test tampering, forbidden secret paths,
  out-of-scope changes, oversized diffs, source deletion, unsafe command
  evidence, symlink bait, workflow changes, and simultaneous violations
- 6 safe mutations covering minimal fixes, allowed source additions, moderate
  in-scope diffs, benign command evidence, harmless filenames, and allowed
  documentation

The catalog uses small deterministic Python fixtures. It is intended to detect
regressions in check behavior, not to represent the frequency or complexity of
production changes.

## Metrics

Reports include:

- total, safe, and unsafe mutation counts
- expected and observed expected detections
- missed, forbidden, and unexpected detections
- safe mutations with any failed check
- controlled mutation detection rate
- safe-fixture pass rate
- per-check opportunities, expected detections, observed detections, misses,
  and unexpected detections
- per-category summaries

The controlled mutation detection rate is observed expected detections divided
by declared expected detections. The safe-fixture pass rate is the percentage
of safe catalog entries with no failed checks.

These terms are deliberately narrow. Controlled mutation detection rate is not
a real-world false-negative rate. Safe-fixture pass rate is not a real-world
false-positive rate. Synthetic mutations do not estimate production violation
prevalence.

To compare how required controlled detections change when exactly one check is
prevented from executing, use the
[policy ablation study](policy-ablation.md). Mutation audit establishes whether
the catalog expectations hold; ablation uses that valid control to calculate
escapes, unique contribution, redundant coverage, and check overlap.

## Expectations And Strict Mode

A mutation fails when an expected detection is missed or a forbidden detection
is observed. Additional failed checks are warnings by default:

```bash
agentguard diagnostics mutations --mutation unsafe_modify_test
```

Strict mode turns every additional unexpected failed check into a mutation
failure:

```bash
agentguard diagnostics mutations --strict
```

`--allow-detection-failures` preserves findings while returning exit code 0,
which is useful for exploratory catalog work. Invalid catalogs, options, and
setup inputs return exit code 2 without an expected validation traceback.

## Reproduction

Run the complete catalog:

```bash
agentguard diagnostics mutations \
  --catalog examples/mutations/catalog.yaml
```

Filter by repeated or comma-separated IDs:

```bash
agentguard diagnostics mutations \
  --mutation unsafe_add_dotenv,unsafe_command_event
```

Filter by category or choose an output root:

```bash
agentguard diagnostics mutations \
  --category secret_paths \
  --output-dir /tmp/agentguard-mutations
```

Default reports are written under:

```text
.agentguard/diagnostics/mutations/<audit-id>/mutations.json
.agentguard/diagnostics/mutations/<audit-id>/mutations.md
```

Generated `.agentguard/` artifacts are ignored and should not be committed.

## Contracts Versus Mutations

[Benchmark contracts](benchmarks.md#contracts-and-audit) validate that complete
benchmark variants still produce their declared functional results, scores,
modified paths, failed checks, and evidence. They test benchmark behavior
through normal benchmark execution.

Mutation testing validates the check layer itself by injecting controlled
evidence and asking whether the expected checks react without alarming on the
safe fixtures. The two layers are complementary: contracts protect benchmark
meaning, while mutations protect detection behavior.

Policy ablation is a third, dependent layer. It reuses the mutation audit
execution and compares control to one-disabled-check conditions. Its
contribution metrics describe only the controlled catalog and do not turn
mutation results into production security claims.

## Limitations

- The catalog covers selected deterministic evidence patterns, not every way a
  policy can be violated.
- Path-based secret detection does not inspect arbitrary file contents.
- Command mutations use predefined events and do not execute unsafe commands.
- Small local fixtures do not reproduce production repository size,
  configuration diversity, or developer behavior.
- Results depend on the selected policies, path patterns, limits, and fixtures.
- Synthetic mutation measurements must not be presented as universal or
  production prevalence claims.
