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

## Live Filesystem Policies

The filesystem guard compares each scan against the pre-agent snapshot and
detects:

- forbidden path creation or modification
- test file modification
- path changes outside `allowed_paths`
- secret-like path creation based on configured `secret_patterns`
- changed-file count above `diff_limits.max_files_changed`
- deletion of files that existed before the agent started
- symlinks that point outside the benchmark workspace

Secret content scanning remains a post-hoc policy check. The online guard only
uses path, metadata, deletion, and symlink evidence.

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

This is event/log based enforcement. It is not syscall interception, shell
auditing, or a kernel sandbox. Commands that an agent executes without
instrumentation and without writing an AgentGuard command event cannot be
blocked by the online command guard, though post-hoc filesystem, command-log,
Docker, CI, and review gates may still catch other evidence.

## Filesystem Polling Model

The first implementation uses portable polling, not platform-specific watcher
APIs. AgentGuard snapshots the workspace before agent execution, then scans the
tree at the configured interval.

The scanner:

- does not follow symlinks
- skips `.git`, common cache directories, and
  `.agentguard_agent_events.jsonl`
- tracks created, modified, deleted, and symlink entries
- bounds scan cost with a maximum observed-file cap
- avoids reading file contents for live policy decisions

## Supported Agents

Runtime termination is supported for:

- `local-command`
- `agent-command`

Docker `custom-command` remains effectively audit-only for this phase because
the termination boundary is the container runner rather than a direct local
agent process.

Mock agents are not long-running subprocesses, so they can be monitored for
audit evidence but are not a meaningful termination target.

## Termination Semantics

In enforce mode, AgentGuard sends a graceful termination signal to the running
agent process. If the process does not exit within a short grace window,
AgentGuard kills it. The report marks the run as `FAIL` with a controlled
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
- Live diff-size enforcement currently covers changed file count, not live
  line-added or line-deleted thresholds.
- Secret content scanning remains post-hoc.
- Command guard enforcement only sees command events appended to the
  AgentGuard event log. It does not observe uninstrumented subprocesses at the
  operating-system level.
- Docker custom-command termination is deferred.
- Ignore handling is limited to built-in AgentGuard/cache paths in this phase.
