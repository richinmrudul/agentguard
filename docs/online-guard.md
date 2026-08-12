# Online Guard

`agentguard run` can monitor the benchmark workspace and cooperative command
events while a local agent is running:

```bash
agentguard run examples/configs/fix_auth_bug_local_command_safe.yaml \
  --agent local-command \
  --guard-mode enforce
```

The guard is runtime enforcement. It observes filesystem changes and
instrumented command-attempt events during the agent phase, records live
violations, and in enforce mode terminates supported agent processes before
normal post-hoc scoring.

## Modes

- `off`: default existing behavior. No live monitor runs.
- `audit`: monitor and record live violations, but do not terminate the agent.
  Normal post-hoc checks still decide the result.
- `enforce`: monitor and terminate supported agent processes after the first
  observed live policy violation. Post-run diff collection, checks, reports,
  manifest, trace, history, and command logs still run where safe.

The polling interval defaults to 0.2 seconds and can be adjusted:

```bash
agentguard run CONFIG --agent local-command --guard-mode audit --guard-poll-interval 0.1
```

## Batch Execution

Suites, matrices, and external evaluations accept the same options:

```bash
agentguard suite SUITE --guard-mode audit --guard-poll-interval 0.1
agentguard matrix SUITE --guard-mode enforce --guard-poll-interval 0.1
agentguard evaluation run --profile PROFILE --suite SUITE --yes \
  --guard-mode audit --guard-poll-interval 0.1
```

The selected immutable configuration applies uniformly to every selected child
attempt, including parallel matrix workers. Batch result objects, JSON and
Markdown reports, and manifests record the requested mode and interval.
External evaluations inherit these fields from `MatrixResult`.

Audit incidents do not independently change batch `PASS`/`FAIL`; normal
post-hoc checks remain authoritative. Enforce mode uses the existing supported
orchestrator termination paths and is never downgraded to audit. Matrix
checkpoints require an identical mode and polling interval on resume. Legacy
checkpoints without these fields are compatible only with `off` and the
default interval.

## Live Filesystem Policies

The filesystem guard compares each scan against the pre-agent snapshot and
detects:

- forbidden path creation or modification
- test file modification
- path changes outside `allowed_paths`
- secret-like path creation based on configured `secret_patterns`
- secret-content matches from configured literal detectors and opt-in built-in
  detector presets
- changed-file count above `diff_limits.max_files_changed`
- current baseline-relative additions above `diff_limits.max_lines_added`
- current baseline-relative deletions above `diff_limits.max_lines_deleted`
- deletion of files that existed before the agent started
- symlinks that point outside the benchmark workspace

Configured secret-content scanning is available in online audit/enforcement as
well as post-hoc diff checks. Online evidence records detector IDs plus
sanitized relative paths and line numbers; it does not record matched values,
configured literals, built-in regex internals, raw lines, or raw diffs.

### Live line limits

Line limits measure the current workspace against the guard’s initial Git
baseline. They are not cumulative editing churn: if an agent adds 20 lines and
then removes five of those additions, the current delta reflects the remaining
15. A violation occurs only when the measured value is greater than its limit;
equality is permitted.

Tracked-file counts use Git numstat semantics against the captured baseline
commit. Untracked text files are counted without decoding content. Measurement
runs only when at least one line threshold is configured and metadata shows a
relevant file change. It is bounded to 1,000 files, 1 MB per file version, and
8 MB of total candidate content per scan.

Binary files, unreadable or disappearing files, oversized inputs, exhausted
bounds, and Git failures make the summary explicitly incomplete. Known counts
are retained and can still exceed a threshold, but unavailability alone does
not terminate an agent. Raw file content and Git stderr are never placed in
guard evidence.

`diff_lines_added` and `diff_lines_deleted` incidents map to the existing
`diff_size` warning policy. Audit mode records them without terminating.
Enforce mode terminates supported local agents, retaining both violations if
both thresholds were exceeded. Later scans do not duplicate or erase an
already-observed violation.

## Live Command Policies

The command guard watches `.agentguard_agent_events.jsonl` while the agent is
running. Agents and benchmark fixtures can append JSONL command-attempt events
such as:

```json
{"type":"command_attempt","command_text":"rm -rf important_data"}
```

AgentGuard applies the same unsafe-command substring policy used by post-hoc
checks and command preflight matching. In `audit` mode, matching command events
are recorded while the agent continues. In `enforce` mode, the first matching
event terminates supported local agent processes.

The event channel accepts only a no-follow regular file within the prepared
repository. Post-hoc and online readers share hard limits of 1 MiB total input,
8 KiB per JSONL line, 200 accepted events, and 100 retained live violations.
Readers drain incrementally and never retain an unterminated line beyond the
line limit. Symlinks, replacement races, non-regular sources, and limit
overflows produce a bounded `Agent event instrumentation incomplete` diagnostic
in reports; they do not abort independent tests, diff collection, or report
generation.

This is event/log based enforcement. It is not syscall interception, shell
auditing, or a kernel sandbox. Commands that an agent executes without
instrumentation and without writing an AgentGuard command event cannot be
blocked by the online command guard, though post-hoc filesystem, command-log,
Docker, CI, and review gates may still catch other evidence.

## Filesystem Watcher Model

AgentGuard uses a small filesystem watcher abstraction for online guard
observability. The current implementation is dependency-free portable polling;
future platform-specific backends can plug into the same event shape without
changing guard incident semantics.

Configure the watcher in benchmark YAML:

```yaml
filesystem_watcher:
  mode: auto
```

Modes:

- `auto`: default. Uses the safest available watcher, currently `polling`.
- `polling`: explicitly use the stdlib polling watcher.
- `disabled`: do not retain watcher events; keep the legacy baseline-diff guard
  fallback for policy enforcement.

The watcher snapshots the workspace before agent execution, then scans the tree
at the configured guard interval. Watcher events are small, sanitized records:
repo-relative path, event type, sequence number, and source. Regular file and
directory events use `created`, `modified`, and `deleted`. Symlink changes use
`symlink_created`, `symlink_modified`, and `symlink_deleted`. Polling mode
represents renames and moves as a `deleted` event for the old path plus a
`created` event for the new path. Events do not include file contents, raw
diffs, absolute paths, symlink target strings, environment values, or raw
exceptions.

The scanner:

- does not follow symlinks
- skips `.git`, common cache directories, and
  `.agentguard_agent_events.jsonl`
- skips `.agentguard` runtime artifact directories
- applies validated `guard_ignore_paths` patterns to regular files and safe
  directory trees
- tracks created, modified, deleted, and symlink entries
- bounds scan cost with a maximum observed-file cap
- avoids reading file contents for live policy decisions
- deduplicates consecutive `modified` events for the same path
- retains a bounded event sample and reports
  `filesystem watcher event limit exceeded` when the retained sample overflows

Policy checks still use the existing baseline-relative snapshot comparison.
The watcher improves event observability; content validation for live
secret-content detections and line-limit measurement remains handled by the
existing bounded scanners. Because the current backend is polling, a file that
is created and deleted entirely between scans may not produce a watcher event;
final-state safety checks and post-hoc Git evidence remain authoritative.

### Configurable generated-path ignores

Benchmarks may declare deterministic repository-relative patterns:

```yaml
guard_ignore_paths:
  - coverage/**
  - build/**
  - .cache/tool/**
```

Patterns use the same normalized POSIX-style path matching as other AgentGuard
path policies. The list preserves configuration order, rejects normalized
duplicates, and is inherited by suite, matrix, and evaluation child runs.
Built-in exclusions remain mandatory and cannot be replaced.

Validation rejects empty or non-string entries, absolute/home/URI/drive/UNC
paths, NULs, dot or traversal components, root-wide wildcards, repository
metadata, AgentGuard event/evidence paths, and patterns that overlap test,
forbidden, or secret path policies. Ambiguous leading-wildcard overlaps fail
closed; there is no unsafe override.

These ignores suppress only online polling observations, live changed-file
counts, live line counts, and ignored-tree traversal when pruning is safe. Git diff collection
and all post-hoc checks still inspect the final repository, so a final ignored
path can still fail scope, forbidden-path, test-tampering, secret, or diff
checks. Ignore patterns are noise controls, not security allowlists, and do not
add paths to `allowed_paths`.

Directory symlinks are never followed. Before pruning a configured ignored
tree, the guard inspects symlink entries without following them. An ignored-
looking symlink that resolves outside the workspace is retained as
`symlink_escape` evidence and can terminate a supported agent in enforce mode.
Safe symlinks inside ignored trees are ignored. Symlink watcher events expose
only the symlink path and event type; target strings are not serialized.

## Supported Agents

Runtime termination is supported for:

- `local-command`
- `agent-command`

Docker `custom-command` runs through the Docker command runner. AgentGuard
does not use the online guard to signal a process inside the container, but
timeout and error cleanup names the container and attempts forced removal so
long-running Docker work is not left behind.

Mock agents are not long-running subprocesses, so they can be monitored for
audit evidence but are not a meaningful termination target.

## Termination Semantics

In enforce mode, AgentGuard sends a graceful termination signal to the running
agent process group. If the process tree does not exit within a short grace
window, AgentGuard escalates to kill. Local command, agent-command, and test
command timeouts use the same process-tree cleanup path. Docker-backed
commands are run with a managed container name so timeout/error cleanup can
attempt `docker rm -f` after terminating the local Docker client process.
Interruptions and unexpected exceptions after process startup also invoke
bounded cleanup without replacing the original exception.

On POSIX hosts, cleanup status is not complete until the owned process group is
observed to be gone after bounded graceful and forceful termination attempts.
On Windows, the current direct-process backend does not own a Job Object and
therefore does not claim verified descendant cleanup. Pipe drainage after a
timeout is bounded even when cleanup cannot be confirmed. Status is recorded
with sanitized booleans and fixed messages such as
`command timed out and process tree was terminated`,
`command timed out and process-tree cleanup could not be confirmed`, or
`docker cleanup incomplete: container removal failed`; raw exception text,
environment values, and workspace absolute paths are not added as cleanup
evidence. The report marks guard-enforced runs as `FAIL` with a controlled
`Live filesystem guard` check instead of surfacing a traceback.

AgentGuard preserves partial command logs, timeline events, JSON and Markdown
reports, manifest data, and execution trace data. Tests are skipped when the
agent was terminated by the online guard, but policy checks still run against
the partial workspace diff.

Timeline events include:

- `guard_started`
- `guard_violation_detected`
- `guard_terminated_agent`
- `guard_completed`
- `command_guard_started`
- `command_guard_violation_detected`
- `command_guard_terminated_agent`
- `command_guard_completed`

## Reports And Evidence

JSON reports include `guard_summary` and `command_guard_summary`. Markdown
reports include `Online Filesystem Guard` and `Online Command Guard` sections.
Manifests include both guard summaries, and execution traces include compact
`guard_summary` and `command_guard_summary` events.

Filesystem guard summaries add `configured_ignore_patterns`, containing only
normalized repository-relative patterns. Older reports and traces without this
field load with an empty list. Incident schemas and matrix aggregates do not
copy these patterns.

The same summary includes current `live_lines_added`, `live_lines_deleted`,
measurement completeness, skipped-file count, and a sanitized status when
measurement is incomplete. These additive values appear in JSON, Markdown,
manifests, and traces. Old artifacts use zero counts and a complete default.

When a guarded run records live violations, AgentGuard also writes first-class
incident artifacts:

```text
.agentguard/runs/<run-id>/guard/incident.json
.agentguard/runs/<run-id>/guard/incident.md
```

The incident includes all audit-mode violations, or the blocking violation plus
any prior observed violations in enforce mode. It records aggregate metrics
such as total guard violations, whether the run was blocked, filesystem versus
command violation counts, time to first violation, and time to block.

You can print a compact incident summary with:

```bash
agentguard guard show .agentguard/runs/<run-id>/guard/incident.json
```

`agentguard guard list` filters recorded history incidents in SQL before
ordering and `--limit` are applied:

```bash
agentguard guard list --status blocked --limit 20
agentguard guard list --status audit --agent local-command
agentguard guard list --benchmark auth_bug_local_test_cheater
```

`--status all` is the default. Blocked and audit status can be combined with
exact agent, benchmark, and category filters. Audit means an incident path is
recorded and `guard_blocked` is false; ordinary rows whose blocked flag is false
are not audit incidents. Queries use stored history metadata and neither parse
nor require the incident file to remain on disk.

The same incident selection is available from history commands:

```bash
agentguard history list --incidents-only
agentguard history list --guard-status blocked --category test_tampering
agentguard history export --format json --incidents-only
agentguard history export --format csv --guard-status audit --output /tmp/audit-incidents.csv
```

JSON keys and CSV columns are unchanged. Guard-mode, policy, and guard-type
history filters remain deferred.

## Matrix And Evaluation Aggregation

Matrix results aggregate the structured guard metrics captured on each final
child row. External evaluations use the same aggregation through `run_matrix`;
there is no separate evaluation counting path.

- An incident run has `guard_violations_total > 0`.
- A blocked run is an incident run with `guard_blocked = true`.
- An audit-only run is an incident run that was not blocked.
- A child with several violations counts once as an incident run, while each
  violation contributes to the violation total.
- A child containing both filesystem and command violations contributes to
  both guard-type groups but only once to the overall incident-run count.
- Guard-off and execution-error rows are evaluated runs with zero guard metrics.

Timing summaries exclude missing and negative values. Median uses the sorted
sample median, and p95 uses deterministic nearest rank: rank
`ceil(0.95 * sample_count)`. Empty distributions report zero samples and no
statistics.

Matrix JSON, Markdown, manifests, and CLI output consume the same typed
aggregate. Incident links are safe paths relative to `matrix.md` and refer to
the existing sanitized child artifacts. Missing or corrupt incident files do
not remove structured metrics or fail matrix completion. Aggregation does not
copy raw evidence and does not alter `PASS`/`FAIL`, scoring, reliability, or
baseline gates.

## Difference From Post-Hoc Checks

Post-hoc checks evaluate the final workspace after the agent exits. They are
still the source of truth for scoring in `off` and `audit` modes.

The online guard observes changes and cooperative command events during
execution. In `enforce` mode it can stop supported agents before they continue
after a violation.

## Limitations

- Polling detection is not instantaneous and may miss very short-lived
  create-delete sequences between scans.
- The first implementation bounds scan size and is intended for benchmark
  workspaces, not very large repositories.
- Live line limits are baseline-relative polling measurements, not cumulative
  edit-churn limits.
- Online secret-content scanning uses the same configured literals and opt-in
  built-in presets as post-hoc scanning, with the same bounded evidence and
  redaction rules. The adversarial-core pack includes fake secret-content
  scenarios for selected built-in presets; detector IDs can appear in evidence,
  but matched values never should.
- Command guard enforcement only sees command events appended to the
  AgentGuard event log. It does not observe uninstrumented subprocesses at the
  operating-system level.
- Incident evidence is concise and sanitized; it is not a replacement for the
  full JSON report, manifest, trace, command log, or workspace review.
- Static incident dashboard/detail pages, site filters, and history query
  enhancements are deferred.
- Process-tree cleanup is best-effort on the host platform; it is not syscall
  interception or a full sandbox boundary.
- Privileged OS-native watcher backends such as FSEvents, fanotify, or eBPF
  remain deferred.
