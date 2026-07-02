# Portable Execution Traces

AgentGuard benchmark runs write a portable execution trace to:

```text
.agentguard/runs/<run-id>/trace.jsonl
```

The current version 2 schema is `agentguard.execution-trace`. A trace contains one
canonical JSON header followed by ordered canonical JSON event records.

## Evidence Model

The header records execution, AgentGuard, benchmark, agent, configuration,
policy, sandbox, and source-artifact identities. Its `trace_id` is the root
content digest rather than a random identifier.

Version 2 also commits to a normalized replay policy snapshot containing the
enabled checks, resolved severities, score weights, path and command patterns,
file-count bounds, diff limits, and command-policy mode. Version 1 remains
parseable and verifiable but normally lacks enough policy evidence for replay.

Events are ordered as:

1. `execution_started`
2. zero or more `agent_command`
3. zero or more `file_change`
4. one `test_result`
5. zero or more `check_result`
6. one `execution_completed`

Command and test events retain sanitized commands, working-directory roles,
status, duration, timeout/truncation state, preflight policy evidence, and
SHA-256 identities for bounded sanitized output. Raw stdout and stderr are not
included.

File events retain repository-relative paths, change type, old/new content
hashes when available, modes, line counts, and safe symlink-target
representation. Full file content is never included. Unified diffs are omitted
by default and are included only with `trace export --include-diff`; included
diffs are bounded and sanitized.

Check events retain bounded sanitized messages and evidence. Completion records
the result, score, changed-file summary, failed/warning check names, duration,
and source report/manifest hashes.

## Integrity

Each event commits to the schema context, sequence, event type, payload,
previous event hash, and optional relative offset using canonical JSON and
SHA-256. The header root hash commits to the final event hash and header
identity fields. Verification rejects modified payloads, altered header
identity, reordering, insertion, deletion, duplicate or gapped sequences,
unsupported schema versions, invalid paths, and truncated files.

These hashes detect accidental or unauthenticated modification. They are not
cryptographic signatures, do not prove who created a trace, and do not prove
agent identity.

## Sanitization And Bounds

Traces reuse AgentGuard's manifest sanitization for known environment values,
secret-like metadata, common token/password/API-key options, authorization
headers, and URL credentials. Environment names may appear; values do not.
Known repository, run, and configuration roots are replaced by symbolic roles.

Strings, evidence lists, argv, changed-file lists, patterns, and optional diffs
are bounded. Truncation metadata is recorded. Sanitization is pattern-based and
cannot guarantee detection of every encoded, transformed, or previously
unknown secret.

## Commands

Inspect a trace without printing raw output or file content:

```bash
agentguard trace show .agentguard/runs/<run-id>/trace.jsonl
```

Verify its schema, event chain, root digest, paths, ordering, and any available
source artifacts:

```bash
agentguard trace verify .agentguard/runs/<run-id>/trace.jsonl
agentguard trace verify .agentguard/runs/<run-id>/trace.jsonl --strict-sources
```

Exit codes are:

- `0`: trace integrity is valid; unavailable optional sources are allowed.
- `1`: the trace is intact but an available source changed, or strict source
  verification found an unavailable source.
- `2`: malformed, corrupt, truncated, or unsupported trace.

Export an older run when its report, command evidence, and prepared repository
are still complete and consistent:

```bash
agentguard trace export .agentguard/runs/<run-id> --output trace.jsonl
agentguard trace export report.json --output trace-with-diff.jsonl --include-diff
```

Export refuses incomplete required evidence and refuses overwrite without
`--force`. It does not fabricate missing events. Detached exports use stable
source roles; source files may be unavailable after relocation while trace
integrity remains verifiable.

Run metamorphic replay robustness checks:

```bash
agentguard trace metamorphic .agentguard/runs/<run-id>/trace.jsonl
agentguard trace metamorphic .agentguard/runs --transform timestamp_variation,add_test_file
```

Metamorphic testing rewrites typed trace models, recomputes integrity hashes,
and replays transformed traces. Preserving transforms should keep outcomes
stable; changing transforms should produce expected policy deltas; invalid
transforms should be rejected.

## Portability And Limitations

Traces capture policy-relevant evidence, not repository snapshots. They omit
raw command output, full file content, host-specific repository roots, and
environment values by default.

Online filesystem guard summary events include normalized configured ignore
patterns when present. The field is additive; older traces without it continue
to verify and load with an empty list. Replay continues to evaluate captured
post-hoc policy evidence, because polling ignores do not alter those policies.

New guard summary events also retain current live added/deleted counts,
measurement completeness, skipped-file count, and a sanitized incomplete
status. Older traces default these fields safely. Replay loads the recorded
summary but does not rerun polling or claim to reproduce violation timing.

Trace validity does not prove benchmark correctness, policy completeness,
agent identity, or that recorded evidence was honestly produced. Traces are
not signed. Schema v2 traces can be replayed through the real checks and scorer
without invoking an agent, model, tests, Docker, network, or the original
repository:

```bash
agentguard trace replayability trace.jsonl
agentguard trace replay trace.jsonl
```

Replay reproduces policy evaluation from captured evidence, not agent behavior.
See [replay.md](replay.md).
