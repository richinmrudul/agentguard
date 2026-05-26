# Running AgentGuard in GitHub Actions

AgentGuard CI mode evaluates the current repository's existing git diff or a
PR-style base/head git diff. It does not run an agent. A typical run executes the
configured test command, applies deterministic policy checks, scores the result, and
writes JSON/Markdown reports.

AgentGuard also ships a reusable composite action. See [docs/action.md](action.md)
for action inputs and an action-based workflow example.

```bash
agentguard ci --config agentguard.yaml
```

For pull request-style evaluation in CI, pass the base and head refs:

```bash
agentguard ci --config agentguard.yaml --base origin/main --head HEAD --github-summary
```

## Diff Modes

- Working-tree mode: `agentguard ci --config agentguard.yaml` evaluates staged,
  unstaged, and untracked local changes.
- Ref mode: `agentguard ci --config agentguard.yaml --base origin/main --head HEAD`
  evaluates committed changes between the merge base of `origin/main` and `HEAD`.

In GitHub Actions, use `actions/checkout` with `fetch-depth: 0` for ref mode.
AgentGuard needs access to the base ref and enough git history to compute the
base/head diff.

## Exit Codes

- `PASS` exits `0`.
- `FAIL` exits `1`.
- `--allow-fail-result` exits `0` even when the policy result is `FAIL`, which is
  useful for expected failing or demo runs.

```bash
agentguard ci --config agentguard.yaml --allow-fail-result
```

## Reports

Each CI run writes reports under:

```text
.agentguard/ci/<run-id>/report.json
.agentguard/ci/<run-id>/report.md
.agentguard/ci/<run-id>/command_log.json
```

The JSON and Markdown reports include the task, result, score, config path, repository
directory, test result, diff summary, check results, command log path, and timeline.

When `--github-summary` is provided, AgentGuard appends a compact Markdown summary to
the file path in `GITHUB_STEP_SUMMARY`. GitHub renders that content on the Actions run
summary page. The summary includes result, score, failed and warning checks, changed
file counts, and report paths; it does not include full command stdout or stderr.

## Example Config

Keep the config in your repository, commonly at `agentguard.yaml`:

```yaml
mode: ci
task_id: pr_safety_check
description: Validate AI-generated code changes before merge.
test_command: pytest
allowed_paths:
  - agentguard/**
  - tests/**
  - examples/**
forbidden_paths:
  - .env
  - secrets/**
test_paths:
  - tests/**
expected_modified_files:
  min: 1
  max: 12
unsafe_commands:
  - rm -rf
  - curl
  - wget
  - nc
  - chmod 777
policy:
  tests_pass:
    severity: error
  forbidden_paths:
    severity: critical
  test_tampering:
    severity: warning
  unsafe_commands:
    severity: critical
  scope_adherence:
    severity: warning
  diff_size:
    severity: warning
  secret_scan:
    severity: critical
diff_limits:
  max_files_changed: 20
  max_lines_added: 800
  max_lines_deleted: 500
secret_patterns:
  - .env
  - "*.pem"
  - "*.key"
  - secrets/**
```

## Complete Workflow

Save this as `.github/workflows/agentguard.yml` in a repository that installs
AgentGuard from source:

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

      - name: Run AgentGuard CI
        run: agentguard ci --config agentguard.yaml --base origin/main --head HEAD --github-summary
```
