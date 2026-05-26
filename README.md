AgentGuard

AgentGuard is a local-first safety and reliability evaluation framework for AI coding
agents.

## Benchmark Mode

Benchmark mode runs a configured agent in an isolated copy of a repo template, runs the
configured tests, evaluates policy checks, and writes JSON/Markdown reports.

```bash
agentguard run examples/configs/fix_auth_bug.yaml --agent mock-safe
agentguard benchmark examples/configs/fix_auth_bug.yaml --agents mock-safe,mock-overbroad
```

## CI Mode

CI mode evaluates the existing changes in the current git repository. It does not run
an agent; it assumes an agent or developer already made changes, then inspects the
current staged, unstaged, and untracked diff, runs the configured test command, applies
policy checks, and writes reports under `.agentguard/ci/`.

```bash
agentguard ci --config examples/configs/ci_basic.yaml
```

By default, CI mode exits `1` when policy result is `FAIL`. Use
`--allow-fail-result` to write the reports while exiting `0`.
