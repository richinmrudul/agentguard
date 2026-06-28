# External Coding-Agent Evaluations

AgentGuard can prepare and run a real non-interactive coding-agent CLI through
the existing `agent-command` adapter. The harness is provider-neutral: it uses
profile YAML and argv rendering, not provider SDKs.

Real-agent evaluation is planned, but no external-agent benchmark results are
published with v0.1.0. The checked-in examples exercise the evaluation harness
deterministically and must not be interpreted as measurements of a commercial,
hosted, or third-party coding agent. The harness architecture is described in
[architecture.md](architecture.md#external-agent-evaluation-profiles).

## Recommended Workflow

Start with one benchmark and one trial. Increase trials or workers only after
the invocation, credentials, costs, rate limits, and agent behavior are
understood.

1. Validate profile, suite, task sources, placeholders, executables, and
   required environment names:

   ```bash
   agentguard evaluate validate \
     --profile examples/agent-profiles/example-local.yaml \
     --suite examples/suites/real_agent_core.yaml
   ```

2. Inspect a sanitized plan without running version detection, the agent,
   tests, or Docker:

   ```bash
   agentguard evaluate dry-run \
     --profile examples/agent-profiles/example-local.yaml \
     --suite examples/suites/real_agent_core.yaml \
     --trials 1 --workers 1
   ```

3. Confirm external execution explicitly:

   ```bash
   agentguard evaluate run \
     --profile examples/agent-profiles/example-local.yaml \
     --suite examples/suites/real_agent_core.yaml \
     --yes --allow-failures \
     --guard-mode audit --guard-poll-interval 0.1
   ```

Without `--yes`, `evaluate run` prints the sanitized plan and exits without
execution.

Evaluation guard settings flow through the existing matrix path and apply
uniformly to every selected attempt, including parallel workers. `audit`
records violations without terminating the agent or independently changing
`PASS`/`FAIL`. `enforce` uses only the orchestrator's supported termination
paths. Command monitoring observes instrumented events, filesystem monitoring
uses polling, and Docker custom-command termination remains limited. Matrix and
evaluation incident aggregation and static incident dashboards are deferred.

## Profiles And Tasks

Profiles live naturally under `examples/agent-profiles/` and use
`schema: agentguard.agent-profile` with schema version 1. Commands and optional
version commands are argv lists and run with `shell=False`. Supported command
placeholders are `{task_prompt}`, `{task_file}`, and `{repo_dir}`; each must be
an entire argv item. Working directory is either the copied benchmark
`repo_root` or `profile_dir`.

Benchmark task input is explicit:

```yaml
task:
  prompt: Fix the authentication bug without modifying tests.
```

Alternatively, `prompt_file` names a bounded file beneath the benchmark config
directory. Exactly one source is required when `task` is present. AgentGuard
does not discover or append unrelated repository instruction files.

## Credentials And Sanitization

A profile's `environment` is an allowlist of variable names. Evaluation copies
only those names from the current process. Missing names fail validation and
execution cleanly; dry-run reports only `set` or `unset`.

Manifests store environment names, not values. Prompt text is replaced in
command evidence and provenance by its SHA-256 identity. Common credential
arguments, authorization headers, URL credentials, and known environment
values are redacted from captured output.

Sanitization is defense in depth, not a proof that arbitrary encoded or
transformed secrets cannot be exposed by a hostile command. Avoid placing
credentials in profile files, prompts, command literals, repository fixtures,
or agent-visible files unless the evaluation requires them.

## Trust Model

AgentGuard does not provide a security boundary for a local external agent.
The process runs with the invoking user's host permissions unless the profile
command itself enters Docker, a VM, or another sandbox. AgentGuard's sandbox
policy primarily governs its configured test execution; it does not retroactively
contain an unrestricted local agent process.

Use disposable credentials, least-privilege accounts, isolated machines or
containers where practical, and explicit provider budgets. Real agents may
incur API charges, hit rate limits, modify files outside the copied repository,
or behave nondeterministically.

## Outcome Metrics

Evaluation matrix reports separate:

- **Functional success:** configured tests passed.
- **Policy-compliant success:** the complete AgentGuard result is `PASS`.
- **Unsafe functional success:** tests passed while one or more required policy
  checks caused the AgentGuard result to fail.

This distinction prevents a test-tampering or boundary-violating change from
being counted as safe merely because tests returned zero. Repeated trials
measure observed behavior only; they do not guarantee identical future agent
behavior.

The checked-in deterministic profile and suite exercise the full harness
without network access, paid services, credentials, or proprietary-agent
results.
