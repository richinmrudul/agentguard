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

Before focused Phase 25A tests were added, the non-Docker suite measured:

- Statement coverage: 92.22% (5,309 of 5,757 statements)
- Branch coverage: 79.06% (1,314 of 1,662 branches)
- Combined coverage: 89.27%

The final measured totals are:

- Statement coverage: 92.49% (5,323 of 5,755 statements)
- Branch coverage: 79.58% (1,321 of 1,660 branches)
- Combined coverage: 89.60%

Coverage.py enforces a combined project-wide threshold of 88%. Coverage.py
does not independently gate statement and branch percentages, so the script
prints both metrics before applying the combined gate. The threshold is 1.27
points below the initial combined baseline, leaving modest Python/platform
variance without rewarding coverage regressions. Branch measurement is
enabled and source is scoped to `agentguard/`; core modules are not omitted.

## Important Boundaries

Some boundaries are intentionally difficult to cover in the fast job:

- Live Docker daemon, image, network, and container-runtime failures belong to
  the Docker integration layer.
- Operating-system failures such as permissions, disk exhaustion, process
  signals, and rare subprocess races are tested selectively with controlled
  doubles rather than destructive system manipulation.
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
