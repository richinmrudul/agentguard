# Benchmark Fuzzing

`agentguard benchmarks fuzz` generates deterministic policy-focused benchmark
variants from small internal templates. The goal is to expand check coverage
around boundary conditions without external agents, network access, Docker, or
mutable hand-authored fixtures.

## Purpose

Benchmark fuzzing stress-tests AgentGuard's existing policy checks with
controlled evidence. It materializes isolated workspaces under the selected
output directory, synthesizes diff and command evidence, runs the real checks,
and compares observed detections with variant expectations.

This is a check-quality diagnostic. It does not measure external agent quality,
production incident rates, or benchmark task difficulty.

## Dimensions

The initial dimensions are:

- `secret-paths`: `.env`, `.npmrc`, `secrets/token.key`, and
  `config/api_key.txt` path variants for secret scanning and forbidden paths.
- `scope-boundaries`: allowed source changes, test paths, docs paths, and
  nested disallowed paths for scope adherence.
- `test-tampering`: assertion deletion, skipped tests, weakened expected
  values, and renamed test files.
- `unsafe-commands`: direct dangerous commands, dangerous arguments, shell
  wrappers, and a benign near miss.
- `diff-size-boundaries`: below, exactly at, and above a configured line
  threshold.
- `path-traversal`: parent traversal, nested traversal, normalized path bait,
  and a symlink-like safe path.

## Deterministic Seeds

Variant generation is deterministic for a given seed. The seed controls variant
ordering and therefore which variants survive `--limit`.

```bash
agentguard benchmarks fuzz --seed agentguard --limit 100 --force
```

Changing the seed changes ordering and limited selection while keeping variant
definitions valid and deterministic.

## Metrics

Reports include:

- total, unsafe, and safe variant counts
- controlled detection rate
- safe-variant pass rate
- per-dimension pass rate
- per-check expected opportunities, observed detections, misses, and unexpected
  detections
- missed expected detections
- forbidden unexpected detections
- safe false alarms
- boundary cases and limitations

JSON and Markdown reports are written to:

```text
.agentguard/fuzz/<study-id>/fuzz.json
.agentguard/fuzz/<study-id>/fuzz.md
```

The JSON schema is `agentguard.benchmark-fuzz` with `schema_version` 1.

## Reproduction

Run every dimension with the default deterministic seed:

```bash
agentguard benchmarks fuzz --force
```

Run a static validation only:

```bash
agentguard benchmarks fuzz --static-only --force
```

Run selected dimensions:

```bash
agentguard benchmarks fuzz \
  --dimension secret-paths,unsafe-commands \
  --dimension diff-size-boundaries \
  --seed release-check \
  --limit 12 \
  --force
```

`--allow-fuzz-failures` keeps exit code 0 while preserving findings in the
reports. Without it, any expectation failure exits 1. Invalid options,
dimensions, output paths, or schema problems exit 2 without a raw traceback.

## Limitations

- Variants synthesize check evidence and do not execute external agents.
- Execution is serialized; `--workers` is preserved as deterministic aggregation
  metadata for compatibility with other benchmark diagnostics.
- Path traversal variants are represented as diff path evidence. Files are
  materialized with sanitized names so the command never writes outside the
  output directory.
- Safe near misses are small templates, not a complete false-positive corpus.

## Related Diagnostics

Benchmark contracts validate that registered benchmark families still behave as
designed when executed normally.

Mutation diagnostics apply a versioned catalog of deterministic safe and unsafe
actions to copied fixtures, then run tests, diff collection, checks, and
scoring.

Benchmark fuzzing differs from both: it uses internal generated templates rather
than permanent fixture files or registry contracts, and it focuses on quickly
expanding policy boundary coverage across many small deterministic variants.
