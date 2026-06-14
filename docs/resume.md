# Resumable Matrix Execution

AgentGuard matrix checkpoints allow an interrupted evaluation to reuse completed
attempts only after their resolved inputs, reports, manifests, hashes, and
history identity are verified.

```bash
agentguard matrix examples/suites/core.yaml \
  --trials 5 --workers 4 \
  --checkpoint .agentguard/checkpoints/core.json

agentguard matrix examples/suites/core.yaml \
  --trials 5 --workers 4 \
  --resume .agentguard/checkpoints/core.json
```

## Lifecycle

`--checkpoint PATH` writes a versioned `agentguard.matrix-checkpoint` document
before execution and updates it after every completed attempt by default.
`--checkpoint-every N` batches completion updates. Writes use a temporary file,
flush, `fsync`, and atomic replacement so a failed write preserves the previous
valid checkpoint.

On a handled interruption, AgentGuard converts unverifiable running entries
back to pending, marks the checkpoint `interrupted`, and exits with code 130. A
completed run marks it `completed` and records the final matrix artifact paths.

## Compatibility

Stable attempt keys include suite and config hashes, benchmark ID/version, agent
or profile/model identity, task prompt hash when applicable, trial index, and
execution-affecting policy and sandbox settings. They exclude timestamps,
random run IDs, and worker count.

Resume rejects changes to the suite, filters, selected agents, trials,
fail-fast setting, benchmark/config identities, profile identity, or attempt
plan. Worker count may change because it affects scheduling, not attempt
meaning.

AgentGuard version or commit changes are explicit compatibility warnings.
`--force-resume` can acknowledge those warnings, and every bypass is recorded.
It cannot bypass schema errors, input hash mismatches, corrupt artifacts, failed
manifest verification, or conflicting history identity.

## Artifact Verification

Before reuse, AgentGuard verifies:

- checkpoint schema and attempt ordering;
- current suite, config, benchmark, profile, prompt, policy, and sandbox
  identities;
- report, Markdown, and manifest existence and stored SHA-256 hashes;
- execution-manifest structure and referenced artifact/config hashes;
- result, score, checks, run ID, benchmark, agent, and prompt identity;
- absence of a conflicting logical history record.

Missing or unverified execution-failure artifacts are rerun. Corrupted completed
artifacts cause a safe refusal rather than silent reuse.

## Failed Attempts

Verified failed attempts are reused by default because they are completed
observations. `--retry-failed` reruns them. Reports separate reused, newly
executed, skipped, retried, and invalidated attempts.

## Reconciliation and History

Reused and new rows are merged by stable ordinal. Reliability, baseline gates,
result totals, reports, manifests, and matrix history consume that reconciled
list exactly once. Existing child history records are upserted by execution ID,
and the matrix retains its original matrix ID.

This provides verified exactly-once logical aggregation and history identity.
It does not claim exactly-once external side effects: an agent process may have
changed systems outside AgentGuard before an interruption.

## Smoke Test

```bash
bash scripts/resume_demo.sh
```

The local demo interrupts a four-attempt mock matrix, inspects the checkpoint,
resumes it, and verifies final completion and reuse in a temporary directory.
A sanitized machine-specific sample is stored in
`docs/results/resume-summary.json`.

## Limitations

- Checkpoints verify AgentGuard-owned artifacts, not arbitrary external state.
- Hard termination cannot run the interruption handler; work absent from the
  last durable update is recomputed.
- Estimated recomputation avoided sums recorded attempt durations and is not a
  promise about future wall time.
- Reusing a valid result does not prove an agent would reproduce it if rerun.
