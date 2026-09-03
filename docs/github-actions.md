# Running AgentGuard in GitHub Actions

## Preset Execution Boundary

The v0.3.0 `minimal`, `recommended`, and `strict` initialization presets
configure settings that `agentguard ci` consumes: test-command time/output
bounds, diff and expected-file thresholds, policy severities, path checks, and
optional built-in secret-content detectors. They perform post-execution
validation and do not contain the coding agent or the configured test command.

The CI path does not apply benchmark-only Docker, command-policy, or filesystem
watcher settings. Use least-privilege runner credentials and an isolation model
appropriate for the code being evaluated. See
[CI policy presets](policy-presets.md) for exact settings and limitations.

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

The production v0.3.0 `agentguard init --ci github` command can
generate a maintained starter workflow at `.github/workflows/agentguard.yml`.
The production PyPI package contains the initializer, and the generated
`agentguard-evals==0.3.0` pin resolves publicly. See
[safe project initialization](project-initialization.md) for its dry-run,
overwrite, detection, and workflow security model.

```bash
agentguard ci --config agentguard.yaml
```

For pull request-style evaluation in CI, pass the base and head commits. Put
event values in environment variables instead of interpolating them into a
shell program:

```bash
agentguard ci --config agentguard.yaml --base "$AGENTGUARD_BASE_SHA" --head HEAD --github-summary
```

## Diff Modes

- Working-tree mode: `agentguard ci --config agentguard.yaml` evaluates staged,
  unstaged, and untracked local changes.
- Ref mode: `agentguard ci --config agentguard.yaml --base origin/main --head HEAD`
  evaluates committed changes between the merge base of `origin/main` and `HEAD`.

In GitHub Actions, use `actions/checkout` with `fetch-depth: 0` for ref mode.
AgentGuard needs access to the base ref and enough git history to compute the
base/head diff.

## Updating Action Pins

Maintained copyable workflows pin third-party and remote Actions to immutable
40-character commit SHAs, with an adjacent comment naming the trusted release or
source revision. To update a pin, resolve the intended upstream release to its
commit, verify the commit belongs to that upstream project, review the upstream
diff and release notes, update the SHA and comment together, and merge the
change through normal human review. Do not configure automated Action updates
that merge without review.

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
.agentguard/ci/<run-id>/pr-report.json
```

The JSON and Markdown reports include the task, result, score, portable config
and repository references, test result, diff summary, check results, portable
command log path, and timeline. Known local roots are written with symbolic
roles such as `${RUN_ROOT}`, `${REPOSITORY_ROOT}`, `${CONFIG_ROOT}`, and
`${AGENTGUARD_ROOT}` so uploaded artifacts do not preserve runner-specific
absolute roots.

Every CI run also writes a versioned `agentguard.pr-report` JSON artifact. Pass
`--baseline-report PATH` to compare against either an earlier CI `report.json`
or an earlier PR report. Finding identities use canonical rule IDs, safe
repository paths, and SHA-256 fingerprints of the full rule-aware semantic
evidence; display truncation is not part of identity. Line numbers are excluded
from content-finding identity so line movement remains stable. Raw commands,
arguments, authorization values, URL credentials, configured unsafe/secret
patterns, and arbitrary check payloads are not copied into PR reports,
summaries, annotations, or IDs. They are represented only by safe outcome
descriptors and, when needed to distinguish findings, one-way fingerprints.
The comparison classifies findings as `new`,
`existing`, or `resolved`; a missing argument is `unavailable`, while an
unreadable, oversized, malformed, wrong-version, or wrong-task baseline is
`invalid`. Versioned PR baselines use strict typed shapes and reject unknown
fields, invalid counts, duplicate identities, or inconsistent fingerprints.
Current and resolved collections are each limited to 1,000 findings, so a fully
replaced maximum-size collection can round-trip while the 5 MB baseline input
bound still applies.

When the baseline is unavailable or invalid, current findings are
`unclassified` rather than being mislabeled as new. The report records the
baseline content digest and filename, not an
environment-specific absolute path.

Baseline classification does not waive policy. The normal exit code continues
to gate on all current error and critical findings: `PASS` is `0`, `FAIL` is
`1`, and operational/input errors are `2`. Thus a missing or corrupt baseline
cannot turn current failures green. Use `--allow-fail-result` only when the
existing documented non-gating behavior is intentional.

When `--github-summary` is provided, AgentGuard appends a compact Markdown summary to
the file path in `GITHUB_STEP_SUMMARY`. GitHub renders that content on the Actions run
summary page. The summary includes result, score, failed and warning checks, changed
file counts, baseline state, bounded new/existing/resolved lists, and report
paths; it does not include full command stdout or stderr. AgentGuard prepares both
summary sections before appending them and rolls back a partial append when the
destination still has the expected size.

If `GITHUB_STEP_SUMMARY` is unset, AgentGuard emits a warning and retains the primary
gate exit (`0` for `PASS`, or `1` for `FAIL` unless `--allow-fail-result` is used).
If the configured summary cannot be created or written, the completed AgentGuard
result is still printed, followed by a sanitized diagnostic; the command exits `2`
and does not claim that the summary was published. This operational exit takes
precedence over the gate exit because summary publication was explicitly requested.

Finding paths are limited to 500 characters, 500 UTF-8 bytes, and 255 characters
per component.
Oversized current or legacy paths become location-free opaque findings; a
versioned baseline containing one is invalid. `--github-annotations` emits at
most ten annotations and only for new findings that have an unambiguous bounded
positive line number in a regular UTF-8 file contained by the repository. The
complete bounded file is validated before annotation. Absolute paths, traversal,
symlinks at any path component, missing/deleted files, binary content, oversized
files or target lines, out-of-range lines, duplicates, and location-free findings
are skipped.
Workflow-command properties and messages are escaped. Existing findings are
not re-annotated.

The example workflows upload retained evidence with
`actions/upload-artifact@v6.0.0`. Workflows that upload hidden `.agentguard`
runtime paths set `include-hidden-files: true`, keep path globs limited to
known AgentGuard filenames under `.agentguard/ci/*`, `.agentguard/suites/*`,
`.agentguard/showcase/*`, or `.agentguard/showcase/suites/*`, and use
`if-no-files-found: error` so a missing evidence set fails clearly. The
SARIF/JUnit example uploads non-hidden export files and keeps hidden-file upload
disabled for that handoff. Generated artifacts remain under `.agentguard/...`
or `docs/results/...`; do not commit `.agentguard/` runtime directories.

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
  - env:
      AGENTGUARD_BASE_SHA: ${{ github.event.pull_request.base.sha }}
    run: agentguard ci --config agentguard.yaml --base "$AGENTGUARD_BASE_SHA" --head HEAD --github-summary
```

The full copyable version, including artifact upload, is
[`examples/github-actions/agentguard-ci.yml`](https://github.com/richinmrudul/agentguard/blob/main/examples/github-actions/agentguard-ci.yml).

## PR Or Job Summary

[`examples/github-actions/agentguard-pr-summary.yml`](https://github.com/richinmrudul/agentguard/blob/main/examples/github-actions/agentguard-pr-summary.yml)
uses a tracked approved baseline with `--baseline-report`, writes the
machine-readable comparison with `--pr-report`, and enables the bounded summary
and safe new-finding annotations. The workflow is compatible with forked pull
requests: it uses only `pull_request`, `contents: read`, the checked-out base
commit SHA through an environment variable, and artifact upload. It does not
use `pull_request_target`, interpolate event data into shell source, request
secrets, or grant write permissions.

The example loads the approved baseline with `git show` from the validated
40-character base commit SHA. It does not trust a baseline modified by the pull
request itself. Command arguments are assembled in a Bash array; the base SHA
and runner paths remain data rather than executable shell source.

An approved baseline is a review decision. Refresh it from a known trusted run
after accepting the findings it contains, then commit it under a stable path
such as `baselines/agentguard-ci.json`. AgentGuard does not fetch or
manage a remote baseline service and does not infer freshness from timestamps.

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
      .agentguard/showcase/showcase-summary.json
      .agentguard/showcase/showcase-summary.md
      .agentguard/showcase/showcase-overhead.json
      .agentguard/showcase/showcase-overhead.md
      .agentguard/showcase/suites/*/suite.json
      .agentguard/showcase/suites/*/suite.md
      .agentguard/showcase/suites/*/manifest.json
    if-no-files-found: error
    include-hidden-files: true
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
- If artifacts are missing, keep failure-evidence upload steps guarded with
  `if: always()`, set `include-hidden-files: true` for `.agentguard` paths, and
  keep `if-no-files-found: error` so missing evidence is visible.
