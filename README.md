AgentGuard

AgentGuard is a local-first safety and reliability evaluation framework for AI coding
agents.

## Usage

- Benchmark one agent: `agentguard run CONFIG_PATH --agent AGENT_NAME`
- Benchmark multiple agents: `agentguard benchmark CONFIG_PATH --agents a,b,c`
- Evaluate existing local changes: `agentguard ci --config agentguard.yaml`
- Evaluate PR-style committed changes:
  `agentguard ci --config agentguard.yaml --base origin/main --head HEAD`

## GitHub Actions

See [docs/github-actions.md](docs/github-actions.md) for a GitHub Actions workflow
example and CI-mode guidance, including `fetch-depth: 0` for base/head PR diffs.
