# Running AgentGuard in GitHub Actions

AgentGuard CI mode evaluates the current repository's existing git diff or a
PR-style base/head git diff. It does not run an agent. A typical run executes the
configured test command, applies deterministic policy checks, scores the result, and
writes JSON/Markdown reports.

AgentGuard also ships a reusable composite action. See [docs/action.md](action.md)
for action inputs and an action-based workflow example.

Copyable workflow examples live under
[`examples/github-actions/`](https://github.com/richinmrudul/agentguard/tree/main/examples/github-actions):

- [`agentguard-ci.yml`](https://github.com/richinmrudul/agentguard/blob/main/examples/github-actions/agentguard-ci.yml): basic
  fail-on-unsafe PR gate with report artifact upload.
- [`agentguard-pr-summary.yml`](https://github.com/richinmrudul/agentguard/blob/main/examples/github-actions/agentguard-pr-summary.yml):
  CI gate plus a concise sanitized GitHub job summary.
- [`agentguard-showcase.yml`](https://github.com/richinmrudul/agentguard/blob/main/examples/github-actions/agentguard-showcase.yml):
  runs the local showcase metrics flow for evaluators.
- [`agentguard-sarif-junit.yml`](https://github.com/richinmrudul/agentguard/blob/main/examples/github-actions/agentguard-sarif-junit.yml):
  exports existing reports to SARIF and JUnit.
- [`agentguard-gate.yml`](https://github.com/richinmrudul/agentguard/blob/main/examples/github-actions/agentguard-gate.yml):
  compares a suite against an approved baseline.

On `main`, the unreleased `agentguard init --ci github` command can generate a
maintained starter workflow at `.github/workflows/agentguard.yml`. The current
PyPI v0.2.2 package does not contain the initializer. See
[safe project initialization](project-initialization.md) for its dry-run,
overwrite, detection, and workflow security model.

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

The example workflows upload JSON, Markdown, command-log, and manifest artifacts
with `actions/upload-artifact@v6.0.0`. Generated artifacts remain under
`.agentguard/...` or `docs/results/...`; do not commit `.agentguard/` runtime
directories.

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
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5.0.1
        with:
          fetch-depth: 0

      - uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405 # v6.2.0
        with:
          python-version: "3.11"

      - name: Install AgentGuard
        run: python -m pip install -e ".[dev]"

      - name: Run AgentGuard CI
        run: agentguard ci --config agentguard.yaml --base origin/main --head HEAD --github-summary
```

## Fail A Pull Request On Unsafe Behavior

Use the basic gate example when you want AgentGuard to block unsafe PRs:

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5.0.1
    with:
      fetch-depth: 0
  - uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405 # v6.2.0
    with:
      python-version: "3.11"
  - run: python -m pip install -e ".[dev]"
  - run: agentguard ci --config agentguard.yaml --base "origin/${{ github.base_ref }}" --head HEAD --github-summary
```

The full copyable version, including artifact upload, is
[`examples/github-actions/agentguard-ci.yml`](https://github.com/richinmrudul/agentguard/blob/main/examples/github-actions/agentguard-ci.yml).

## PR Or Job Summary

[`examples/github-actions/agentguard-pr-summary.yml`](https://github.com/richinmrudul/agentguard/blob/main/examples/github-actions/agentguard-pr-summary.yml)
uses `--github-summary` so the Actions run page shows the AgentGuard result,
failed checks, changed-file counts, guard incident counts when available, and
report locations. It appends only static artifact pointers after the run and
does not render raw diffs, secret values, environment variables, or full
stdout/stderr blobs.

## Showcase Metrics In CI

For reviewers evaluating the repository itself, run the deterministic showcase
metrics flow:

```yaml
- run: python scripts/showcase_metrics.py
- uses: actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f # v6.0.0
  with:
    name: agentguard-showcase-metrics
    path: |
      docs/results/showcase-summary.json
      docs/results/showcase-summary.md
      docs/results/showcase-metrics.json
      docs/results/showcase-metrics.md
      .agentguard/showcase/**/*.json
      .agentguard/showcase/**/*.md
```

The full workflow is
[`examples/github-actions/agentguard-showcase.yml`](https://github.com/richinmrudul/agentguard/blob/main/examples/github-actions/agentguard-showcase.yml).
It is local, non-Docker, and network-free after checkout and dependency
installation.

## Permissions

Most AgentGuard examples need only:

```yaml
permissions:
  contents: read
```

SARIF upload to GitHub Code Scanning additionally requires
`security-events: write`. Do not add `pull-requests: write`, `checks: write`,
or broad repository write permissions unless your own workflow adds commenting,
annotations, or other write operations outside AgentGuard.

## Troubleshooting

- If base/head diff collection fails, ensure `actions/checkout` uses
  `fetch-depth: 0`.
- If `agentguard.yaml` is missing, copy the config shape from this page and
  adapt `allowed_paths`, `forbidden_paths`, and `test_command`.
- If expected unsafe demo scenarios fail the job, use suite baselines or
  `--allow-fail-result` only for demo/evidence jobs, not merge-blocking gates.
- If artifacts are missing, keep upload steps guarded with `if: always()` so
  reports are preserved after a failed gate.
