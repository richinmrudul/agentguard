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
- [External-agent evaluations](docs/evaluation.md): profile validation,
  dry-run planning, credentials, trust boundaries, and safety metrics.

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
agent_version_command:
  - my-agent
  - --version
agent_model: coding-model-v1
agent_metadata:
  provider: internal
  temperature: 0
```

`agent_version_command` accepts the same string-or-argv shape as
`agent_command`, runs with `shell=False`, and is bounded by timeout and output
limits. Detection failure produces a warning but does not fail evaluation.
`agent_metadata` accepts only scalar string, integer, float, or boolean values.

## Real-Agent Evaluations

Provider-neutral agent profiles describe a non-interactive coding-agent CLI
without adding a provider SDK to AgentGuard. Profiles use argv lists and the
complete-item placeholders `{task_prompt}`, `{task_file}`, and `{repo_dir}`.
Benchmark configs supply an inline `task.prompt` or a bounded `task.prompt_file`.

Start with the deterministic, network-free example:

```bash
agentguard evaluate validate --profile examples/agent-profiles/example-local.yaml --suite examples/suites/real_agent_core.yaml
agentguard evaluate dry-run --profile examples/agent-profiles/example-local.yaml --suite examples/suites/real_agent_core.yaml --trials 3 --workers 2
agentguard evaluate run --profile examples/agent-profiles/example-local.yaml --suite examples/suites/real_agent_core.yaml --yes --allow-failures
```

Dry-run output shows prompt source and SHA-256, sanitized argv, selected
benchmarks, attempt counts, and whether required environment variable names are
set. It does not execute version detection, agents, tests, or Docker. Execution
copies only profile-allowlisted environment values from the current process;
reports and manifests retain names, never values.

Matrix output distinguishes functional success (configured tests passed) from
policy-compliant success (the complete AgentGuard result is `PASS`). An unsafe
functional success passed tests but failed an AgentGuard policy check.

Local external agents are not contained by AgentGuard and run with host-user
permissions unless their command provides a separate sandbox. Validate and
dry-run first, consider cost and rate limits, and begin with one benchmark and
one trial. See [docs/evaluation.md](docs/evaluation.md) for the full workflow.

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
agentguard matrix examples/suites/core.yaml --agent mock-safe --trials 5 --workers 4 --allow-failures
```

Without `--agent`, matrix mode preserves each suite row's configured agent. With
one or more repeated `--agent` options, it filters the suite first and then runs
every remaining config once per requested agent. `--trials N` then runs each
filtered benchmark/agent combination `N` times. `--workers N` uses a bounded
thread pool to run independent attempts concurrently; it defaults to `1` for
the existing serial behavior. Every attempt retains an independent run
directory, copied benchmark workspace, command evidence, reports, and history
record. Choose a worker count that fits available host and Docker CPU, memory,
and I/O capacity.

`--fail-fast` stops scheduling new attempts after the first failed result.
Attempts already running are allowed to finish, and reports distinguish
attempts planned from attempts executed and state that execution stopped early.
Reliability rates and comparisons use executed attempts only. Repeated trials
measure observed reliability under those runs; they are not a deterministic
guarantee about future behavior.

Matrix baselines use the same stable baseline format as suites:

```bash
agentguard matrix examples/suites/core.yaml --agent mock-safe --allow-failures --save-baseline baselines/core-matrix.json
agentguard matrix examples/suites/core.yaml --agent mock-safe --allow-failures --compare-baseline baselines/core-matrix.json
```

Repeated matrices can also save a dedicated reliability baseline and gate a
later run against it:

```bash
agentguard matrix examples/suites/core.yaml --agent mock-safe --trials 5 --allow-failures --save-reliability-baseline baselines/core-reliability.json
agentguard matrix examples/suites/core.yaml --agent mock-safe --trials 5 --allow-failures --compare-reliability-baseline baselines/core-reliability.json --min-success-rate 80 --max-success-rate-drop 5 --max-average-score-drop 5
```

Reliability gates compare stable benchmark/config and agent combinations.
Configured drops are allowed up to and including the threshold; a larger drop
is a regression. Reports include 95% Wilson score confidence intervals for
observed pass probability. With few trials, including `--trials 1`, these
intervals are broad. They describe observed results and do not prove future
behavior, determinism, or statistical significance.

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
- Run manifests: `.agentguard/runs/.../manifest.json`
- Suite manifests: `.agentguard/suites/.../manifest.json`
- Matrix manifests: `.agentguard/matrices/.../manifest.json`
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

## Execution Provenance

Every run, suite, and matrix writes a versioned execution manifest after its
JSON and Markdown reports. Manifests identify the AgentGuard version and source
revision, host and optional Docker version, evaluated source revision, config
and suite SHA-256 hashes, resolved execution options, agent adapter/version/model,
benchmark IDs and versions, command and sandbox policies, artifact paths, and
suite or matrix parent-child execution IDs. Matrix manifests also record agents,
trials, workers, execution mode, and executed attempt counts.

Verify that a manifest is structurally valid and its referenced configs are
unchanged:

```bash
agentguard manifest verify .agentguard/runs/RUN_ID/manifest.json
agentguard manifest show .agentguard/runs/RUN_ID/manifest.json
```

Verification exits `0` when available inputs match, `1` when a referenced input
changed or is missing, and `2` for invalid JSON or schema. It never runs an
agent or benchmark.

Manifests deliberately omit full environment variables and raw stdout/stderr.
Configured agent environment variable names are recorded without values.
Secret-sensitive metadata values and common credential-bearing argument forms
such as `--token`, `--api-key`, `--password`, authorization headers, and URL
credentials are redacted. Sanitization is defensive pattern matching, not a
proof that an unrecognized positional secret cannot be exposed; avoid placing
secrets directly in arbitrary command arguments or metadata.

Provenance manifests make inputs and execution policy inspectable and improve
reproducibility. They do not guarantee identical results from nondeterministic
agents, external services, mutable dependencies, host scheduling, or unpinned
toolchains.

## Benchmarks

The benchmark registry at `examples/benchmarks/registry.yaml` gives benchmark
families stable IDs and versions. The current core suite has 12 runs: 6
expected pass and 6 expected fail. See [docs/benchmarks.md](docs/benchmarks.md)
for the full catalog and expected evidence.

List registered benchmarks:

```bash
agentguard benchmarks list
agentguard benchmarks show prompt_injection_readme
agentguard benchmarks generate-suite --output examples/suites/registry_core.yaml --include safe --include adversarial --force
```

Generated suites are ordinary suite YAML files, so they can be filtered,
baselined, and run with the existing `agentguard suite` command.

Each registered benchmark also has a versioned behavior contract. Audit the
registry/config/contract wiring without running agents, tests, or Docker:

```bash
agentguard benchmarks audit --static-only
```

Execute every deterministic safe/adversarial fixture and compare observed
results, scores, changed paths, failed checks, and evidence against its
contract:

```bash
agentguard benchmarks audit --trials 3 --workers 2
agentguard benchmarks audit --benchmark auth_bug --strict-unexpected-checks
```

Repeated trials are marked unstable when result, functional-test outcome,
failed-check set, or modified-file set changes. Unexpected failed checks are
warnings by default and become contract failures in strict mode. Contracts
validate that the benchmark corpus still behaves as designed; they do not
measure the quality of an external agent.

Example suite output:

```text
AgentGuard Suite Summary
Suite: core
Runs: 12
Passed: 6
Failed: 6
Pass rate: 50.0%
Average score: 62

Most common failed checks:
- Scope adherence: 6
- Forbidden paths: 4
- Secret scan: 4
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
