# CI Standard Exports

AgentGuard can export existing report JSON into standards used by CI and
security tooling:

```bash
agentguard reports export-sarif .agentguard/ci/latest/report.json \
  --output agentguard.sarif --force

agentguard reports export-junit .agentguard/matrices/core/matrix.json \
  --output agentguard-junit.xml --suite-name "AgentGuard Matrix"
```

Exports read reports that AgentGuard already wrote. They do not rerun agents,
tests, Docker, or policy checks.

## Supported Inputs

SARIF supports:

- Run and CI report JSON files with `check_results`.
- Suite JSON and matrix JSON. Child run reports are loaded when available so
  SARIF findings include the original check evidence and paths.
- Directories containing supported report JSON files. Unsupported JSON files are
  skipped during directory discovery.

JUnit supports:

- Run and CI report JSON files.
- Suite and matrix JSON files.
- Multi-agent benchmark summary JSON files.
- Mutation audit, policy ablation, and matrix stress diagnostic JSON files when
  they map to deterministic pass/fail cases.
- Directories containing supported report JSON files.

Raw trace JSONL files are not exported directly in this phase. Replay or export
reports first, then export those reports to SARIF or JUnit.

## SARIF Mapping

SARIF output uses version `2.1.0`. AgentGuard check names become SARIF rules
with stable lowercase rule IDs. Severity maps to SARIF levels as follows:

- `critical` and `error` -> `error`
- `warning` -> `warning`
- `info` and passed checks -> `note`

Failed checks are emitted by default. Passed checks are emitted only with
`--include-passed`, using SARIF `kind: pass` and informational level `note`.

Locations come from check evidence and changed-file summaries. Paths are
normalized to repository-relative URIs; absolute local paths, temp paths,
secret-like values, raw command output, and full diffs are not included.
Findings without paths are still emitted with a clear message.

## JUnit Mapping

For a single run, AgentGuard emits one JUnit testcase per policy check. This is
the clearest model for CI test-report viewers because each check appears as an
independent pass/fail item.

For suite, matrix, and benchmark summaries, AgentGuard emits one testcase per
attempt or row. Row-level testcases point to child report paths when available
and summarize failed checks in `failure` and `system-out`.

Diagnostic reports are mapped to deterministic cases:

- Mutation audit: one testcase per mutation.
- Policy ablation: one testcase for the study outcome.
- Matrix stress: one testcase for the integrity outcome.

Invalid input, unsupported schemas, or output overwrite conflicts are CLI
errors with exit code `2`; they are not encoded as JUnit failures.

## GitHub Actions

GitHub Code Scanning upload requires `security-events: write` permission on the
workflow job that calls `github/codeql-action/upload-sarif`. Keep that
permission out of jobs that check out, install, build, test, or evaluate
pull-request-controlled repository code. A copyable example lives at
[`examples/github-actions/agentguard-sarif-junit.yml`](https://github.com/richinmrudul/agentguard/blob/main/examples/github-actions/agentguard-sarif-junit.yml).
Use [`examples/github-actions/agentguard-ci.yml`](https://github.com/richinmrudul/agentguard/blob/main/examples/github-actions/agentguard-ci.yml)
or [`examples/github-actions/agentguard-pr-summary.yml`](https://github.com/richinmrudul/agentguard/blob/main/examples/github-actions/agentguard-pr-summary.yml)
when you only need a merge-blocking CI gate, Markdown/JSON artifacts, and the
GitHub job summary. SARIF/JUnit are optional exports for Code Scanning and
test-report viewers.

The SARIF/JUnit example uses a two-job boundary:

- `evaluate` has `contents: read`, checks out the repository with checkout
  credential persistence disabled, installs AgentGuard, runs evaluation, exports
  SARIF/JUnit, and uploads only those intended files as short-retention
  artifacts. It does not receive `security-events: write`.
- `upload-sarif` depends on `evaluate`, downloads the exported artifact, and
  uploads the SARIF file to Code Scanning. Its only explicit permission is
  `security-events: write`; it does not check out the repository or execute
  repository-controlled build, test, package-install, or script commands.

This boundary does not make SARIF parsing itself risk-free. It prevents
pull-request-controlled repository code from executing in the job that holds
the privileged Code Scanning token.

Code Scanning SARIF upload is appropriate for trusted branch pushes and
same-repository pull requests. The example skips the privileged upload job for
fork pull requests, where Code Scanning upload is unavailable or inappropriate,
while still publishing the JUnit artifact from `evaluate`. If the upload
job is skipped, no Code Scanning upload occurred; use the JUnit artifact or the
unprivileged AgentGuard artifacts for review.

Minimal isolated SARIF upload shape:

```yaml
permissions:
  contents: read

jobs:
  evaluate:
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405 # v6.2.0
        with:
          python-version: "3.11"
      - run: python -m pip install -e .
      - run: agentguard ci --config agentguard.yaml --base origin/main --head HEAD
      - run: agentguard reports export-sarif .agentguard/ci --output agentguard.sarif
      - uses: actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f # v6.0.0
        with:
          name: agentguard-sarif-${{ github.run_id }}-${{ github.run_attempt }}
          path: agentguard.sarif
          if-no-files-found: error
          retention-days: 7
          include-hidden-files: false

  upload-sarif:
    needs: evaluate
    if: >-
      github.event_name == 'push' ||
      (github.event_name == 'pull_request' &&
      github.event.pull_request.head.repo.full_name == github.repository)
    permissions:
      security-events: write
    steps:
      - uses: actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131 # v7.0.0
        with:
          name: agentguard-sarif-${{ github.run_id }}-${{ github.run_attempt }}
          path: agentguard-exports
      - uses: github/codeql-action/upload-sarif@6f5948dfacef28e207b48d0905cf90c03365536d # v3
        with:
          sarif_file: agentguard-exports/agentguard.sarif
```

## Limitations

- SARIF is for policy findings, not benchmark reliability metrics.
- Aggregate SARIF is richest when child run report JSON files are present.
- Exports are intentionally bounded and sanitized; they do not include full
  command stdout/stderr or full diffs.
- The example workflow is documentation only and is not active project CI.
