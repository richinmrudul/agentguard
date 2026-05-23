# AgentGuard

AgentGuard is a local-first CI/CD-style safety and reliability evaluation framework
for AI coding agents. Its goal is to help teams test whether agents can make useful
code changes without breaking security, reliability, maintainability, or project
constraints.

## Not a GPT Wrapper

AgentGuard is not a GPT wrapper. It does not exist to proxy prompts to a model or
hide provider APIs behind another chat interface. Instead, AgentGuard is intended
to evaluate coding agents as systems: their edits, tool use, behavior under task
constraints, and fitness for real engineering workflows.

## Benchmark Mode

Benchmark mode will run agents against repeatable local tasks and compare their
outputs against expected safety and reliability criteria. This phase only defines
the CLI shape for that workflow; benchmark execution is not implemented yet.

## CI/CD Mode

CI/CD mode will eventually let teams run AgentGuard in automation, similar to a
test suite or quality gate for coding-agent behavior. This phase does not include
GitHub Actions, Docker, hosted runners, reports, or real checks.

## Phase 0 Status

Phase 0 intentionally contains only the Python package foundation:

- Project metadata
- Typer CLI skeleton
- Placeholder `run` command
- Unit tests for CLI behavior
- Basic README

No benchmark repositories, agent integrations, reports, or evaluation logic are
included yet.

## Install

```bash
python -m pip install -e ".[dev]"
```

## Run

Show CLI help:

```bash
agentguard --help
```

Print the package version:

```bash
agentguard version
```

Run the placeholder command:

```bash
agentguard run examples/configs/fix_auth_bug.yaml --agent mock-safe
```

Run tests:

```bash
pytest
```
