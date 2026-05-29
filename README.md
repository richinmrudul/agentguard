# AgentGuard

AgentGuard is a local-first, CI/CD-style safety and reliability evaluation
platform for AI coding agents. It runs agents against benchmark repos or real PR
diffs, then evaluates deterministic evidence: tests, git diffs, changed files,
command logs, sandbox metadata, policy checks, and reports.

It is not a GPT wrapper. AgentGuard does not ask a model whether an agent did a
good job; it inspects what changed, what ran, what passed, and what policy
evidence says before a change is trusted or merged.

## Status

| Area | Current state |
|---|---|
| Runtime | Local CLI with benchmark and CI modes |
| CI | GitHub Actions docs and reusable composite action |
| Sandbox | Local and Docker execution, network/resource policies, timeouts |
| Evidence | Test results, diffs, command events, sandbox metadata, timelines |
| Reports | JSON, Markdown, suite reports, baselines, local report browser |

## Why AgentGuard Exists

AI coding agents can make tests pass while doing unsafe or misleading things:
rewriting tests, touching secrets, exceeding scope, following prompt injections
in repo files, or running risky commands. Tests are necessary, but they are not
enough.

AgentGuard treats agents as untrusted contributors. It evaluates the repository
state and execution evidence around the agent's work so reviewers and CI systems
can catch unsafe behavior before merge.

## What AgentGuard Detects

- Test tampering and weakened test suites
- Forbidden path changes and secret-pattern access
- Unsafe command usage
- Scope violations outside allowed paths
- Oversized diffs and unexpected file churn
- Command timeouts and truncated output
- Prompt-injection-following behavior
- Filesystem boundary and sandbox escape attempts

## Quick Demo

```bash
scripts/demo.sh
```

The demo runs safe and adversarial agents, then writes reports under
`.agentguard/`. See [docs/demo.md](docs/demo.md) for the full walkthrough.

## Core Commands

Run a safe Docker-backed benchmark:

```bash
agentguard run examples/configs/fix_auth_bug_docker_command_safe.yaml --agent custom-command
```

Run the same style of command locally, without Docker:

```bash
agentguard run examples/configs/fix_auth_bug_local_command_safe.yaml --agent local-command
```

`custom-command` remains the preferred adapter when you want Docker isolation.
`local-command` runs `agent_command` directly in the copied benchmark repo for
convenience and real local-agent workflows. It is not sandboxed; AgentGuard still
evaluates the resulting tests, diffs, command logs, and policy evidence.

Run an expected-failing prompt-injection benchmark:

```bash
agentguard run examples/configs/prompt_injection_readme_injection_follower.yaml --agent custom-command --allow-fail-result
```

Run the core benchmark suite:

```bash
agentguard suite examples/suites/core.yaml --allow-failures
```

Filter by benchmark metadata:

```bash
agentguard suite examples/suites/core.yaml --category prompt_injection --allow-failures
```

Save a regression baseline:

```bash
agentguard suite examples/suites/core.yaml --allow-failures --save-baseline baselines/core.json
```

Browse local reports:

```bash
agentguard reports list
agentguard reports show --latest --type suite
```

## Example Suite Output

```text
AgentGuard Suite Summary
Suite: core
Runs: 8
Passed: 4
Failed: 4
Pass rate: 50.0%
Average score: 75

Most common failed checks:
- Test tampering: 2
- Forbidden paths: 2
- Secret scan: 2
```

## Architecture

The evaluation pipeline is intentionally simple:

```text
CLI -> Config -> Orchestrator -> Sandbox/Agent -> Tests/Diff/Checks -> Scoring -> Reports
```

Read [docs/architecture.md](docs/architecture.md) for the full system design,
trust model, benchmark flow, CI flow, sandbox model, and limitations.

## Benchmark Catalog

| Scenario | Category | What it exercises |
|---|---|---|
| Auth bug | Source fix / test tampering | Safe source repair versus weakening tests |
| CLI parser bug | Source fix / test tampering | Parser repair versus test cheating |
| Prompt-injection README | Prompt injection / secret access | Ignoring malicious repo instructions |
| Filesystem boundary | Filesystem boundary / sandbox escape | Preventing parent traversal and secret writes |

Suites support metadata filtering by category, difficulty, and tags.

## CI and GitHub Actions

AgentGuard CI mode evaluates an existing repository instead of copying a
benchmark fixture. It can inspect the working tree or PR-style `base`/`head`
refs, write JSON and Markdown CI reports, exit nonzero on blocking policy
failures, and append a compact GitHub step summary.

- [docs/github-actions.md](docs/github-actions.md): CI mode and workflow setup
- [docs/action.md](docs/action.md): reusable composite action inputs and example

## Deterministic Evidence

AgentGuard decisions are based on evidence that can be inspected and archived:

- Test command result and output limits
- Git diff summary, changed files, and line counts
- Command log with executed, blocked, timed-out, and policy-matched commands
- Sandbox metadata such as Docker network, CPU, memory, and timeout settings
- Policy check results with severities and evidence
- JSON/Markdown reports, timelines, suite summaries, and baseline comparisons

This is why AgentGuard is not a GPT wrapper: it does not score self-reported
agent claims. It scores observed behavior.

## Reports and Baselines

AgentGuard writes local artifacts under `.agentguard/`:

- Run reports: `.agentguard/runs/.../reports/report.json` and `report.md`
- CI reports: `.agentguard/ci/.../report.json` and `report.md`
- Command logs: `command_log.json`
- Suite reports: `.agentguard/suites/.../suite.json` and `suite.md`
- Regression baselines for detecting score, pass-rate, and failed-check changes
- Report browser commands for listing and summarizing recent local reports

Generated `.agentguard/` artifacts are ignored and should not be committed.

## Install and Develop

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check .
```

## Roadmap

- Stronger sandbox isolation beyond the current Docker model
- Benchmark registry and benchmark versioning
- Local non-Docker agent adapter
- Optional real LLM/coding-agent adapters
- Backend, run history, and dashboard for team-scale evaluation
