# Testing and Quality

AgentGuard uses layered tests so fast behavioral feedback stays separate from
environment-dependent validation.

## Test Layers

- Unit tests exercise configuration, policy checks, provenance, reports,
  history, scoring, and orchestration helpers without Docker.
- Non-Docker integration tests exercise real repository copies, local command
  agents, suites, matrices, diagnostics, and CLI workflows.
- Docker integration tests are marked `docker` and validate container
  execution and Docker-backed benchmark behavior. The package build and
  installed-wheel smoke tests are marked `package`.

The default coverage job runs unit and non-Docker integration tests, excluding
both `docker` and `package` markers:

```bash
bash scripts/coverage.sh
```

Use `bash scripts/coverage.sh --html` for `coverage/html/index.html`. Use
`bash scripts/coverage.sh --full` to include Docker-gated tests when a Docker
daemon is available. XML is always written to `coverage/coverage.xml`.

## Coverage Baseline and Gate

The authoritative dated snapshot for the current public documentation is
[`results/validation-summary.md`](results/validation-summary.md). At commit
`4ab779307a96827e8f979e02cb9e08276a84bb26`, the non-Docker coverage command
reported:

- Statement coverage: 91.45%
- Branch coverage: 80.45%
- Combined coverage: 88.83%

Coverage.py enforces a combined project-wide threshold of 88%. Coverage.py
does not independently gate statement and branch percentages, so the script
prints both metrics before applying the combined gate. Branch measurement is
enabled and source is scoped to `agentguard/`; core modules are not omitted.
Exact counts and percentages are commit-scoped rather than permanent project
claims.

## Important Boundaries

Some boundaries are intentionally difficult to cover in the fast job:

- Live Docker daemon, image, network, and container-runtime failures belong to
  the Docker integration layer.
- Operating-system failures such as permissions, disk exhaustion, process
  signals, and rare subprocess races are tested selectively with controlled
  doubles rather than destructive system manipulation.
- Process cleanup coverage uses short-lived subprocess fixtures and pid
  sentinels to verify timeout/enforcement cleanup without long sleeps. Docker
  cleanup behavior is unit-tested with controlled doubles and covered by
  Docker integration tests only when a Docker daemon is available.
- Defensive fallbacks for corrupt external files are tested where behavior is
  meaningful, but exhaustive malformed-input combinations are not a goal.

The non-Docker coverage job must not be interpreted as full coverage of
Docker-only execution paths.

## Interpreting Coverage

Coverage identifies code that tests did not execute; it does not prove that
assertions are meaningful, that security properties are complete, or that
real environments match test doubles. AgentGuard pairs coverage with
behavioral assertions, package validation, Docker integration, benchmark
contracts in [benchmarks.md](benchmarks.md), and policy mutation diagnostics in
[detection-quality.md](detection-quality.md).
