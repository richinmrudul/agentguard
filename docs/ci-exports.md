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
workflow job. A copyable example lives at
[`examples/github-actions/agentguard-sarif-junit.yml`](../examples/github-actions/agentguard-sarif-junit.yml).
Use [`examples/github-actions/agentguard-ci.yml`](../examples/github-actions/agentguard-ci.yml)
or [`examples/github-actions/agentguard-pr-summary.yml`](../examples/github-actions/agentguard-pr-summary.yml)
when you only need a merge-blocking CI gate, Markdown/JSON artifacts, and the
GitHub job summary. SARIF/JUnit are optional exports for Code Scanning and
test-report viewers.

Minimal SARIF upload shape:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5.0.1
    with:
      fetch-depth: 0
  - uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405 # v6.2.0
    with:
      python-version: "3.11"
  - run: python -m pip install -e .
  - run: agentguard ci --config agentguard.yaml --base origin/main --head HEAD
  - run: agentguard reports export-sarif .agentguard/ci --output agentguard.sarif
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: agentguard.sarif
```

## Limitations

- SARIF is for policy findings, not benchmark reliability metrics.
- Aggregate SARIF is richest when child run report JSON files are present.
- Exports are intentionally bounded and sanitized; they do not include full
  command stdout/stderr or full diffs.
- The example workflow is documentation only and is not active project CI.
