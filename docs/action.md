# AgentGuard Composite GitHub Action

The reusable AgentGuard action wraps `agentguard ci` in a composite GitHub Action.
It runs CI policy checks against either the current working tree diff or a PR-style
base/head git diff.

This action is intentionally small: it does not install AgentGuard. Install
AgentGuard in the workflow before invoking the action.

## Inputs

| Input | Default | Description |
|---|---|---|
| `config` | `agentguard.yaml` | Path to the AgentGuard config file. |
| `base` | empty | Base git ref for PR-style diff comparison. |
| `head` | `HEAD` | Head git ref for PR-style diff comparison. |
| `github-summary` | `true` | Whether to append a GitHub Actions step summary. |
| `allow-fail-result` | `false` | Whether to exit 0 even if AgentGuard policy result is FAIL. |

When `base` is provided, the action runs:

```bash
agentguard ci --config "$config" --base "$base" --head "$head"
```

When `base` is empty, the action uses working-tree CI mode:

```bash
agentguard ci --config "$config"
```

## Example Workflow

Use `fetch-depth: 0` for base/head diff mode. AgentGuard needs the base ref and
enough git history to compute the diff.

```yaml
name: AgentGuard

on:
  pull_request:
  push:

jobs:
  agentguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install AgentGuard
        run: python -m pip install -e ".[dev]"

      - uses: richinmrudul/agentguard/action@main
        with:
          config: agentguard.yaml
          base: origin/main
          head: HEAD
          github-summary: "true"
```

## Current Limitations

- The action is composite and assumes `agentguard` is already on `PATH`.
- The action does not package or install AgentGuard yet.
- Future Docker sandboxing is separate and is not part of this action.
- The action does not call GitHub APIs, create PR comments, or emit annotations.
