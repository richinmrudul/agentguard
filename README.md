AgentGuard

AgentGuard is a local-first safety and reliability evaluation framework for AI coding
agents.

## Usage

- Benchmark one agent: `agentguard run CONFIG_PATH --agent AGENT_NAME`
- Benchmark multiple agents: `agentguard benchmark CONFIG_PATH --agents a,b,c`
- Evaluate existing local changes: `agentguard ci --config agentguard.yaml`
- Evaluate PR-style committed changes:
  `agentguard ci --config agentguard.yaml --base origin/main --head HEAD`
- Append a GitHub Actions run summary:
  `agentguard ci --config agentguard.yaml --base origin/main --head HEAD --github-summary`

## GitHub Actions

See [docs/github-actions.md](docs/github-actions.md) for a workflow example and
CI-mode guidance, including `fetch-depth: 0` for base/head PR diffs and
`--github-summary` for Actions run summaries.
