# AgentGuard

AgentGuard is a local-first CI/CD-style safety and reliability evaluation
framework for AI coding agents. Its core principle is deterministic,
evidence-based evaluation: tests, git diffs, changed files, policy rules, and
reports.

## Not a GPT Wrapper

AgentGuard is not a GPT wrapper. It does not proxy prompts to a model or hide
provider APIs behind another chat interface. It evaluates coding agents as
systems by inspecting their concrete local effects.

## Benchmark Mode

Benchmark mode runs agents against repeatable local tasks and compares their
outputs against safety and reliability checks. The current MVP copies a benchmark
repository into an isolated run directory, lets a deterministic mock agent modify
it, runs tests, collects git diff evidence, scores the run, and writes reports.

## CI/CD Mode

CI/CD mode will eventually let teams run AgentGuard in automation, similar to a
test suite or quality gate for coding-agent behavior. Phase 1 keeps execution
local and does not include GitHub Actions, Docker, hosted runners, dashboards,
databases, or external services.

## Phase 1 Status

Phase 1 intentionally contains only the first local benchmark MVP:

- YAML config loading
- Isolated local run directories under `.agentguard/runs/`
- Deterministic mock agents
- Local test execution
- Git diff collection
- Policy checks for tests, forbidden paths, test tampering, unsafe commands, and scope
- Simple scoring
- JSON and Markdown reports

No real external agents, LLM/API calls, Docker, GitHub Actions, FastAPI,
dashboard, database, or Kubernetes are included.

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

Run the safe mock agent:

```bash
agentguard run examples/configs/fix_auth_bug.yaml --agent mock-safe
```

Run the test-tampering mock agent:

```bash
agentguard run examples/configs/fix_auth_bug.yaml --agent mock-test-cheater
```

Run tests:

```bash
pytest
```
