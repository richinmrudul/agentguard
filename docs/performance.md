# Performance Diagnostics

AgentGuard includes a deterministic, non-Docker overhead diagnostic:

```bash
agentguard benchmark-overhead \
  --config examples/configs/fix_auth_bug.yaml \
  --agent mock-safe \
  --iterations 10 \
  --warmups 2
```

The command measures one specific benchmark on the current machine. It does not
establish a universal AgentGuard performance claim.

## Methodology

Each pair performs equivalent functional work against a fresh isolated copy of
the configured fixture:

1. The direct workload copies the source fixture, executes the configured
   fixture agent action, and runs the configured tests.
2. The AgentGuard workload calls the normal `run_benchmark` path, including its
   repository preparation, agent execution, tests, evidence checks, reports,
   history index, and execution manifest.
3. The direct and AgentGuard test exit codes, changed paths, and changed-file
   SHA-256 hashes must match. The diagnostic aborts if they differ.

Warmup pairs run first and are excluded from statistics. Measured pairs
alternate direct-first and AgentGuard-first order to reduce ordering bias. All
runs are serial and use `time.perf_counter`. Subprocess startup time remains in
the measurements; AgentGuard does not estimate or subtract it.

The direct path intentionally excludes AgentGuard's git baseline, checks,
reports, history, and manifest. It retains source copying because both workloads
need an isolated fixture. This avoids comparing a no-op with a complete
benchmark while still treating AgentGuard-specific preparation as overhead.

## Measured Stages

AgentGuard records real elapsed time around:

- configuration loading
- workspace preparation
- agent setup and version detection
- agent execution
- test execution
- diff and policy/check evaluation
- command log and report writing
- history writing
- manifest writing

`other_orchestration` is the measured total minus those explicit stage
boundaries. It covers small orchestration work between stages. It is not
created by dividing or estimating the total.

For direct duration, AgentGuard duration, and paired absolute overhead, the
report includes minimum, maximum, mean, median, sample standard deviation, and
p95. A one-sample standard deviation is `0.0`. p95 uses the deterministic
nearest-rank method: sort values and select rank `ceil(0.95 * n)`.

The report also includes paired relative overhead, slowdown ratio, throughput
in runs per minute, raw timings, functional outcomes, and AgentGuard stage
percentages.

## Reproduction

Use the reusable script from any directory:

```bash
/path/to/agentguard/scripts/benchmark_overhead.sh
```

The first optional argument sets measured iterations. The second sets the JSON
output path:

```bash
scripts/benchmark_overhead.sh 20 /tmp/agentguard-overhead.json
```

The script resolves the repository root, uses the deterministic `mock-safe`
auth fixture, runs two warmups, and writes matching JSON and Markdown files.
Set `AGENTGUARD_PYTHON` to choose another Python executable.

Without `--output`, the CLI writes:

```text
.agentguard/benchmarks/overhead-<timestamp>.json
.agentguard/benchmarks/overhead-<timestamp>.md
```

These generated artifacts are ignored by Git. Existing output is protected
unless `--force` is supplied. `--no-history` and `--no-manifest` are available
for targeted diagnostics, but the default comparison includes both.

## Interpretation

Use the raw paired results and medians to compare changes on the same machine,
Python version, configuration, and workload. Record the AgentGuard commit,
operating system, architecture, Python version, date, config SHA-256, warmups,
and iterations when sharing a result.

An overhead percentage from a small local fixture should not be projected onto
other agents or repositories. Long-running external agents, network calls,
large test suites, and Docker startup can dominate total runtime, which usually
reduces AgentGuard's relative instrumentation overhead even when absolute
instrumentation time remains similar.

## Limitations

- Operating-system, interpreter, and filesystem caches cannot be fully
  controlled.
- Host load, power state, storage, antivirus/indexing, and background processes
  can affect results.
- Alternating order reduces but does not remove temporal bias.
- The diagnostic executes serially and does not characterize concurrent suite
  or matrix throughput.
- The default mock fixture is deterministic and network-free, but it is much
  smaller than many production repositories.
- Results are machine- and workload-specific and are not universal performance
  claims.
