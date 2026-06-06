# AgentGuard

AgentGuard is a local-first evaluation harness that treats AI coding agents as
untrusted contributors and judges their work from deterministic evidence:
tests, diffs, command logs, sandbox metadata, policy checks, and reports.

AgentGuard helps teams:

- Run safe and adversarial coding-agent benchmarks in local or Docker-backed
  environments.
- Detect test tampering, forbidden path changes, secret-pattern writes, unsafe
  commands, scope drift, and oversized diffs.
- Compare single runs, benchmark suites, and CI evaluations with JSON and
  Markdown reports.
- Save suite baselines and gate future runs against score, result, failed-check,
  and benchmark-version regressions.
- Browse local report history for demos, debugging, and lightweight trend
  analysis.

Docs:

- [Architecture](docs/architecture.md): pipeline, trust model, sandbox model,
  suite/baseline/history/gate layers, and limitations.
- [Demo](docs/demo.md): copyable 90-second demo flow.
- [Benchmarks](docs/benchmarks.md): core suite, registry families, expected
  safe/adversarial behavior, and evidence checks.

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
agentguard --help
```

Run the demo:

```bash
scripts/demo.sh
```

Run a safe Docker-backed benchmark:

```bash
agentguard run examples/configs/fix_auth_bug_docker_command_safe.yaml --agent custom-command
```

Run the same style of command locally, without Docker:

```bash
agentguard run examples/configs/fix_auth_bug_local_command_safe.yaml --agent local-command
```

Run any configured local command-line agent through the generic adapter:

```bash
agentguard run examples/configs/fix_auth_bug_agent_command_safe.yaml --agent agent-command
```

`custom-command` remains the preferred adapter when you want Docker isolation.
`local-command` runs `agent_command` directly in the copied benchmark repo for
convenience and real local-agent workflows. It is not sandboxed; AgentGuard
still evaluates the resulting tests, diffs, command logs, and policy evidence.
`agent-command` is the generic local adapter for arbitrary command-line coding
agents. It runs with `shell=False`, supports either a command string or argv
list, and is not sandboxed unless the command itself invokes Docker or another
sandbox.

Generic agent command config:

```yaml
agent_name: my-local-agent
agent_command:
  - my-agent
  - --task
  - fix
agent_environment:
  AGENT_MODE: benchmark
agent_workdir: repo_root
```

Run an expected-failing benchmark:

```bash
agentguard run examples/configs/fix_auth_bug_agent_command_cheater.yaml --agent agent-command --allow-fail-result
```

## Suites And Gates

Run the core suite:

```bash
agentguard suite examples/suites/core.yaml --allow-failures
```

Filter by benchmark metadata:

```bash
agentguard suite examples/suites/core.yaml --category prompt_injection --allow-failures
```

Save a baseline and gate against it:

```bash
agentguard suite examples/suites/core.yaml --allow-failures --save-baseline baselines/core.json
agentguard gate suite examples/suites/core.yaml --baseline baselines/core.json --allow-failures
```

Run a suite as an agent matrix:

```bash
agentguard matrix examples/suites/core.yaml --agent mock-safe --allow-failures
agentguard matrix examples/suites/core.yaml --agent mock-safe --agent mock-test-cheater --category prompt_injection --allow-failures
```

Without `--agent`, matrix mode preserves each suite row's configured agent. With
one or more repeated `--agent` options, it filters the suite first and then runs
every remaining config once per requested agent. Matrix reports compare results
by agent, benchmark row, category, and difficulty.

Matrix baselines use the same stable baseline format as suites:

```bash
agentguard matrix examples/suites/core.yaml --agent mock-safe --allow-failures --save-baseline baselines/core-matrix.json
agentguard matrix examples/suites/core.yaml --agent mock-safe --allow-failures --compare-baseline baselines/core-matrix.json
```

`agentguard gate suite` runs a benchmark suite, compares it with a saved suite
baseline, and exits nonzero when the gate detects a regression or invalid
input. The usual flow is:

1. Run the suite and save an approved baseline.
2. Store that baseline in the repository or durable CI storage.
3. Run the gate in pull requests and compare the current suite result with the
   approved baseline.

`--allow-failures` is useful for adversarial benchmark suites because some
benchmarks are expected to fail: they demonstrate unsafe agent behavior such as
test tampering, prompt-injection following, or secret-path writes. The CI gate
should compare the current behavior to the accepted baseline instead of failing
just because those intentionally adversarial cases still fail.

GitHub Actions can run the gate after checkout and dependency setup:

```yaml
- name: AgentGuard gate
  run: agentguard gate suite examples/suites/core.yaml --baseline baselines/core.json --allow-failures
```

See the copyable workflow at
[examples/github-actions/agentguard-gate.yml](examples/github-actions/agentguard-gate.yml).

## Reports, History, And Baselines

AgentGuard writes local artifacts under `.agentguard/` by default:

- Run reports: `.agentguard/runs/.../reports/report.json` and `report.md`
- Suite reports: `.agentguard/suites/.../suite.json` and `suite.md`
- Matrix reports: `.agentguard/matrices/.../matrix.json` and `matrix.md`
- CI reports: `.agentguard/ci/.../report.json` and `report.md`
- Command logs: `command_log.json`
- Timeline data embedded in reports
- Run history index: `.agentguard/history.db`

Regression baselines are written wherever you pass `--save-baseline`; the
examples use `baselines/core.json`.

Browse reports:

```bash
agentguard reports list
agentguard reports show --latest --type suite
```

Inspect history:

```bash
agentguard history list
agentguard history list --type suite --result FAIL
agentguard history stats
agentguard history stats --type suite
agentguard history trends --name core --type suite
agentguard history export --format csv --output /tmp/agentguard-history.csv
agentguard history export --format json --type suite --output /tmp/suites.json
```

History exports are useful for external analysis, demos, spreadsheet workflows,
and dashboard prototypes. They use the local SQLite history index; JSON and
Markdown reports remain the source of truth.

## Benchmarks

The benchmark registry at `examples/benchmarks/registry.yaml` gives benchmark
families stable IDs and versions. The current core suite has 10 runs: 5
expected pass and 5 expected fail. See [docs/benchmarks.md](docs/benchmarks.md)
for the full catalog and expected evidence.

List registered benchmarks:

```bash
agentguard benchmarks list
agentguard benchmarks show prompt_injection_readme
agentguard benchmarks generate-suite --output examples/suites/registry_core.yaml --include safe --include adversarial --force
```

Generated suites are ordinary suite YAML files, so they can be filtered,
baselined, and run with the existing `agentguard suite` command.

Example suite output:

```text
AgentGuard Suite Summary
Suite: core
Runs: 10
Passed: 5
Failed: 5
Pass rate: 50.0%
Average score: 62

Most common failed checks:
- Scope adherence: 5
- Forbidden paths: 3
- Secret scan: 3
- Test tampering: 2
```

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
- Optional real LLM/coding-agent adapters
- Backend, richer run history, and dashboard for team-scale evaluation
