# AgentGuard Composite GitHub Action

The reusable AgentGuard action wraps `agentguard ci` in a composite GitHub Action.
It runs CI policy checks against either the current working tree diff or a PR-style
base/head git diff.

This action is intentionally small: it does not install AgentGuard. Install
AgentGuard in the workflow before invoking the action.

Copyable workflows pin remote Actions to reviewed 40-character commit SHAs.
The AgentGuard action example below uses source revision
`5e93b179f8add85bd4e8d5fa330f97ae1212c109`, the reviewed repository commit
used for the v0.3.0 documentation line; that commit contains `action/action.yml`.
When updating an Action pin, verify the upstream release or source revision,
review the diff, update the adjacent comment, and merge through the normal PR
review path. Do not enable automated Action updates that merge without human
review.

## Inputs

| Input | Default | Description |
|---|---|---|
| `config` | `agentguard.yaml` | Path to the AgentGuard config file. |
| `base` | empty | Base git ref for PR-style diff comparison. |
| `head` | `HEAD` | Head git ref for PR-style diff comparison. |
| `github-summary` | `true` | Whether to append a GitHub Actions step summary. |
| `baseline-report` | empty | Prior CI or PR report used to classify findings. |
| `pr-report` | empty | Explicit path for the machine-readable comparison report. |
| `github-annotations` | `false` | Emit bounded annotations for new findings with safe locations. |
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
enough git history to compute the diff. The workflow declares read-only
`GITHUB_TOKEN` permissions because checkout and AgentGuard only need repository
contents; token permissions do not sandbox commands run from your repository, so
review repository-controlled workflow steps with the same care as any CI code.

```yaml
name: AgentGuard

on:
  pull_request:
  push:

permissions:
  contents: read

jobs:
  agentguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5.0.1
        with:
          fetch-depth: 0
          persist-credentials: false

      - uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405 # v6.2.0
        with:
          python-version: "3.11"

      - name: Install AgentGuard
        run: python -m pip install -e ".[dev]"

      - uses: richinmrudul/agentguard/action@5e93b179f8add85bd4e8d5fa330f97ae1212c109 # reviewed source revision for v0.3.0 docs
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
- The action does not call GitHub APIs or create PR comments. Optional
  annotations are escaped workflow commands, capped at ten, and limited to new
  findings with safe repository-contained file and line locations.
