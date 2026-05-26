AgentGuard

AgentGuard is a local-first safety and reliability evaluation framework for AI coding
agents.

## Usage

- Benchmark one agent: `agentguard run CONFIG_PATH --agent AGENT_NAME`
- Benchmark multiple agents: `agentguard benchmark CONFIG_PATH --agents a,b,c`
- Evaluate existing local changes: `agentguard ci --config agentguard.yaml`

## GitHub Actions

See [docs/github-actions.md](docs/github-actions.md) for a GitHub Actions workflow
example and current CI-mode guidance. Phase 3B CI mode evaluates working tree diffs;
true PR base/head diff comparison is planned for Phase 3C.
