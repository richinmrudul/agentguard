# AgentGuard

AgentGuard is a local-first evaluation harness that treats AI coding agents as
untrusted contributors and judges their work from deterministic evidence:
tests, diffs, command logs, sandbox metadata, policy checks, and reports.

AgentGuard helps teams:

- Run safe and adversarial coding-agent benchmarks in local or Docker-backed
  environments.
- Detect test tampering, forbidden path changes, secret-pattern writes,
  configured secret-content literals, unsafe commands, scope drift, and
  oversized diffs.
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
- [Benchmark packs](docs/benchmark-packs.md): deterministic export, verify,
  inspect, and import workflow for portable benchmark families.
- [Benchmark pack signing](docs/benchmark-pack-signing.md): optional detached
  signatures and local trust policies for pack import gates.
- [Benchmark pack indexes](docs/benchmark-pack-index.md): static local indexes
  for listing, verifying, and installing curated packs.
- [Benchmark fuzzing](docs/benchmark-fuzzing.md): deterministic policy-focused
  benchmark variants, metrics, and limitations.
- [External-agent evaluations](docs/evaluation.md): profile validation,
  dry-run planning, credentials, trust boundaries, and safety metrics.
- [Evaluation Results](docs/results/evaluation-report.md): consolidated
  release, coverage, detection, scale, replay, and limitations summary.
- [Performance diagnostics](docs/performance.md): deterministic overhead
  methodology, reproduction, interpretation, and limitations.
- [Detection quality](docs/detection-quality.md): controlled policy mutations,
  check sensitivity, safe-fixture behavior, and limitations.
- [Policy ablation](docs/policy-ablation.md): single-check contribution,
  overlap, escapes, and controlled-study limitations.
- [Scalability diagnostics](docs/scalability.md): synthetic matrix scheduler,
  history integrity, memory, and fail-fast scaling.
- [Resumable matrices](docs/resume.md): verified checkpoints, interruption,
  artifact validation, and deterministic reconciliation.
- [Portable traces](docs/traces.md): sanitized evidence, hash-chain integrity,
  export, inspection, verification, and limitations.
- [Deterministic replay](docs/replay.md): offline policy reconstruction,
  equivalence reporting, schema compatibility, and limitations.
- [Testing and quality](docs/testing.md): test layers, coverage measurement,
  CI gate, and known limits.
- [Changelog](CHANGELOG.md): draft v0.1.0 capabilities and future changes.
- [Release process](docs/release.md): validation, artifact review, and deferred
  manual release steps.
- [MIT License](LICENSE): terms for using and distributing AgentGuard.

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
agentguard --help
```

## Installation Verification

AgentGuard supports Python 3.9, 3.10, 3.11, and 3.12. CI tests each listed
version; versions not listed are not currently claimed as supported.

Install from a source checkout:

```bash
python -m pip install .
```

For development, install AgentGuard and its test tools in editable mode:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Build and validate a wheel and source distribution without publishing:

```bash
bash scripts/build_release.sh
```

Install the resulting wheel:

```bash
python -m pip install dist/agentguard-*.whl
agentguard --version
```

Verify a real package build and installed console script in a disposable
environment:

```bash
bash scripts/package_smoke.sh
```

The smoke script builds a wheel and source distribution, installs only the
wheel's runtime dependencies in an isolated temporary virtual environment, and
runs the installed `agentguard` CLI. The `examples/` directory is
repository-relative and is not included in the Python package, so the script
explicitly copies those files into its temporary working directory before
running a local-command auth benchmark. Docker is only required for
Docker-backed benchmarks; the package smoke workflow and compatibility test
matrix use non-Docker coverage. The full integration CI job runs Docker-gated
tests once on Python 3.11.

Run the demo:

```bash
scripts/demo.sh
```

Measure instrumentation overhead with the deterministic local fixture:

```bash
agentguard benchmark-overhead --iterations 10 --warmups 2
```

The JSON and Markdown results are machine- and workload-specific diagnostics,
not universal performance claims. See [docs/performance.md](docs/performance.md).

Audit policy-check detection with deterministic safe and unsafe mutations:

```bash
agentguard diagnostics mutations
```

This reports a controlled mutation detection rate and safe-fixture pass rate,
not production false-negative or false-positive rates. See
[docs/detection-quality.md](docs/detection-quality.md).

Measure each policy check's controlled mutation contribution:

```bash
agentguard diagnostics ablation --trials 3 --workers 2
```

See [docs/policy-ablation.md](docs/policy-ablation.md) for definitions,
interpretation, and limitations.

Stress bounded matrix scheduling with a synthetic internal workload:

```bash
agentguard diagnostics matrix-stress
```

See [docs/scalability.md](docs/scalability.md). Synthetic attempts per second
are not coding-agent throughput.

Generate deterministic policy-focused benchmark variants without Docker,
network access, or external agents:

```bash
agentguard benchmarks fuzz --limit 100 --force
```

This reports controlled detection coverage and safe-variant pass rate across
path, secret, command, diff-size, scope, traversal, and test-tampering
boundaries. See [docs/benchmark-fuzzing.md](docs/benchmark-fuzzing.md).

Minimize any fuzz failures and write reviewable regression promotion packages:

```bash
agentguard benchmarks fuzz --minimize-failures --promote-failures /tmp/agentguard-fuzz-promotions --allow-fuzz-failures --force
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

Every benchmark run also writes a portable, sanitized trace:

```bash
agentguard trace show .agentguard/runs/<run-id>/trace.jsonl
agentguard trace verify .agentguard/runs/<run-id>/trace.jsonl
agentguard trace replayability .agentguard/runs/<run-id>/trace.jsonl
agentguard trace replay .agentguard/runs/<run-id>/trace.jsonl
agentguard trace metamorphic .agentguard/runs/<run-id>/trace.jsonl
agentguard trace export .agentguard/runs/<run-id> --output trace.jsonl
```

Trace hashes detect modification but are not signatures. Traces omit raw
stdout, stderr, and full file content by default. Replay executes the captured
policy evaluation, not the agent or tests. Metamorphic trace testing mutates
verified traces to measure replay/check robustness without rerunning external
work. See [docs/traces.md](docs/traces.md), [docs/replay.md](docs/replay.md),
and [docs/metamorphic-traces.md](docs/metamorphic-traces.md).

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

Enable the same online guard configuration for every selected suite run or
matrix attempt:

```bash
agentguard suite examples/suites/core.yaml --guard-mode audit --guard-poll-interval 0.1 --allow-failures
agentguard matrix examples/suites/core.yaml --workers 4 --guard-mode enforce --guard-poll-interval 0.1 --allow-failures
```

Batch guard mode defaults to `off`. Batch JSON, Markdown, manifests, and matrix
checkpoints record the requested mode and finite positive polling interval.
Matrix and external-evaluation results also aggregate child guard incidents.
An incident run has at least one observed guard violation; a blocked run is an
incident run terminated by a supported guard path, and an audit-only run is an
incident run that was not blocked. Run counts and violation counts are separate:
several violations in one child still count as one incident run. Reports include
overall and per-agent, benchmark, category, and guard-type totals plus
deterministic timing distributions. Child incident links are relative references
to sanitized artifacts and become unavailable if those optional files are
missing; the structured metrics remain valid.

Checkpoint an interruptible matrix and resume only verified attempts:

```bash
agentguard matrix examples/suites/core.yaml --trials 5 --workers 4 --checkpoint .agentguard/checkpoints/core.json
agentguard matrix examples/suites/core.yaml --trials 5 --workers 4 --resume .agentguard/checkpoints/core.json
```

See [resumable matrix execution](docs/resume.md) for compatibility, corruption,
retry, history, and external-side-effect limitations.

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

Run with online guard enforcement:

```bash
agentguard run examples/configs/fix_auth_bug_local_command_safe.yaml --agent local-command --guard-mode enforce
```

`--guard-mode audit` records live filesystem and instrumented command-policy
violations without stopping the agent. `--guard-mode enforce` terminates
supported local agent process groups when a live violation is detected. Local
agent, external agent, and test-command timeouts also attempt process-tree
cleanup; Docker-backed commands attempt managed container removal on timeout or
cleanup failure. Command guard enforcement is based on AgentGuard command/event
logs, not kernel-level syscall interception; filesystem monitoring uses
polling. See [docs/online-guard.md](docs/online-guard.md).

Benchmark configs can suppress known generated noise from online filesystem
polling:

```yaml
guard_ignore_paths:
  - coverage/**
  - build/**
  - .cache/tool/**
```

Patterns are normalized repository-relative paths and apply only to online
polling. They do not change Git diff collection, allowed paths, post-hoc checks,
scoring, command monitoring, or incident meaning. Broad, traversing, protected,
or overlapping patterns are rejected, and escaping symlinks remain visible.

When `diff_limits.max_lines_added` or `max_lines_deleted` is configured, the
online filesystem guard also measures the current baseline-relative line delta.
Values must exceed a limit to trigger; equality is allowed. Audit records
`diff_lines_added` or `diff_lines_deleted`, while enforce terminates supported
agents. Binary, unreadable, or bounded-out files make measurement explicitly
incomplete instead of silently counting as zero. Post-hoc Git diff checks remain
authoritative.

Post-hoc secret scanning has two independent inputs. `secret_patterns` remain
path/pattern checks against changed filenames. `secret_content_patterns` are
bounded, literal, case-sensitive substring detectors for newly introduced added
content:

```yaml
secret_content_patterns:
  - id: demo-api-token
    contains: "DEMO_API_TOKEN_"
```

Detector literals and matched secret values are used only inside the scanner.
Reports, manifests, traces, replay output, history, incidents, and CLI output
show detector IDs plus sanitized relative paths/line numbers, never raw secret
content. This check is post-hoc only; live online secret-content audit or
enforcement remains deferred.

Guarded runs with violations write concise incident artifacts under
`.agentguard/runs/<run-id>/guard/`; inspect them with:

```bash
agentguard guard show .agentguard/runs/<run-id>/guard/incident.json
agentguard guard list --status blocked --limit 20
agentguard guard list --status audit --agent local-command
agentguard guard list --benchmark auth_bug_local_test_cheater
```

Matrix JSON, Markdown, manifests, and CLI summaries roll up those child metrics
without copying raw incident evidence or changing matrix scoring. External
evaluations inherit the same aggregation because they execute through matrix
mode. Static report-site incident dashboards remain deferred.

Export reports for CI/security tools:

```bash
# GitHub Code Scanning accepts SARIF 2.1.0.
agentguard reports export-sarif .agentguard/ci/latest/report.json --output agentguard.sarif --force

# CI test-report viewers accept JUnit XML.
agentguard reports export-junit .agentguard/suites/core/suite.json --output agentguard-junit.xml --suite-name "AgentGuard"
```

See [docs/ci-exports.md](docs/ci-exports.md) for supported inputs, mappings,
and a GitHub Actions example.

Generate a local static report site:

```bash
agentguard reports site --output /tmp/agentguard-site --include-results-docs --force
```

The static site is self-contained HTML/CSS with optional local JavaScript for
filtering. It includes matrix guard rollups plus a filtered incident index and
sanitized incident detail pages discovered from existing run artifacts. It
does not copy raw commands, incident files, full diffs, or full trace payloads.
Corrupt or oversized incidents degrade to unavailable rows. See
[docs/static-site.md](docs/static-site.md) for usage, publishing notes, and
sanitization limits.

Inspect history:

```bash
agentguard history list
agentguard history list --type suite --result FAIL
agentguard history list --incidents-only
agentguard history list --guard-status blocked --category test_tampering
agentguard history stats
agentguard history stats --type suite
agentguard history trends --name core --type suite
agentguard history export --format csv --output /tmp/agentguard-history.csv
agentguard history export --format json --type suite --output /tmp/suites.json
agentguard history export --format json --incidents-only
agentguard history export --format csv --guard-status audit --output /tmp/audit-incidents.csv
```

History exports are useful for external analysis, demos, spreadsheet workflows,
and dashboard prototypes. Incident, status, agent, benchmark, and category
filters are applied to stored SQLite metadata before ordering and `LIMIT`;
incident files need not exist and are never parsed for these queries. Audit
means a recorded incident that was not blocked, so ordinary non-incident rows
are excluded. JSON and Markdown reports remain the source of truth.

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
Configured secret-content detector literals are also treated as sensitive
redaction inputs and are not serialized into manifests.

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

Export selected benchmarks as a deterministic portable pack and verify it
before import:

```bash
agentguard benchmarks pack export --benchmark auth_bug --output /tmp/auth-benchmark.zip --include-docs --force
agentguard benchmarks pack verify /tmp/auth-benchmark.zip
agentguard benchmarks pack sign /tmp/auth-benchmark.zip --key /tmp/pack-keys/ci.private-key.json --output /tmp/auth-benchmark.sig.json
agentguard benchmarks pack index create --pack /tmp/auth-benchmark.zip --signature /tmp/auth-benchmark.sig.json --base-dir /tmp --output /tmp/pack-index.yaml --force
agentguard benchmarks pack index verify /tmp/pack-index.yaml
agentguard benchmarks pack import --pack /tmp/auth-benchmark.zip --dest /tmp/agentguard-imported-benchmarks --dry-run
```

See [docs/benchmark-packs.md](docs/benchmark-packs.md) for the pack format,
security model, and review workflow. See
[docs/benchmark-pack-signing.md](docs/benchmark-pack-signing.md) for optional
signatures and trust policies, and
[docs/benchmark-pack-index.md](docs/benchmark-pack-index.md) for static local
indexes.

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

Generate deterministic fuzz variants from small internal templates:

```bash
agentguard benchmarks fuzz --dimension secret-paths,unsafe-commands --force
```

Fuzz studies write JSON and Markdown under `.agentguard/fuzz/` and compare
expected detections with observed check failures. They expand policy boundary
coverage without adding permanent fixture files.

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

The repository CI tests Python 3.9 through 3.12, runs Ruff once, runs the full
Docker-backed integration suite on Python 3.11, and builds validated wheel and
source-distribution artifacts. Those artifacts are uploaded to the workflow run
for inspection only. CI does not publish to PyPI, create tags, or create GitHub
releases.

## Release Status

Release validation is intentionally separate from publication:

```bash
bash scripts/build_release.sh
bash scripts/package_smoke.sh
```

The wheel contains the importable `agentguard` package and console entry point.
The source distribution additionally contains build metadata and the README.
Repository examples, docs, tests, workflows, generated `.agentguard` data,
local databases, caches, and development scripts are excluded from both
artifacts.

Publishing remains a later explicit phase. The repository currently has no
published package, tag, or GitHub release. See the
[release process](docs/release.md) for validation and the manual steps reserved
for a future phase, and the [changelog](CHANGELOG.md) for the draft v0.1.0
notes.

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
bash scripts/coverage.sh
```

## License

AgentGuard is available under the [MIT License](LICENSE).

## Roadmap

- Stronger sandbox isolation beyond the current Docker model
- Optional real LLM/coding-agent adapters
- Backend, richer run history, and dashboard for team-scale evaluation
