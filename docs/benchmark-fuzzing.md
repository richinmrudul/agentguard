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
- minimized failures and reduction metrics
- promotion package paths
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

## Minimization

When a fuzz variant fails its expectation, minimization can reduce it to a
smaller reproducible case:

```bash
agentguard benchmarks fuzz \
  --minimize-failures \
  --max-minimize-steps 50 \
  --allow-fuzz-failures \
  --force
```

The minimizer first reproduces the original failure signature. It then tries
deterministic simplification passes and accepts only changes that preserve the
same expectation failure. Passes include removing unrelated modified files,
reducing to a single violation, shortening paths while preserving triggering
patterns, reducing diff size while preserving threshold crossings, simplifying
commands, and normalizing descriptions.

Complexity is deterministic and combines:

- file count
- modified path count
- command count
- total path length
- diff line count
- evidence item count
- weighted sum

Reports include original and minimized complexity, reduction percentage, steps
attempted, steps accepted, reproduced yes/no, failure preserved yes/no, and the
final expected/observed checks. Non-reproducible failures are kept as structured
findings instead of raw tracebacks.

## Promotion Workflow

Promotion writes reviewable files for maintainers. It does not edit the
benchmark registry, benchmark contracts, or core suites.

Fixture package:

```bash
agentguard benchmarks fuzz \
  --minimize-failures \
  --promote-failures /tmp/agentguard-fuzz-promotions \
  --promotion-format fixture \
  --allow-fuzz-failures \
  --force
```

Patch package:

```bash
agentguard benchmarks fuzz \
  --minimize-failures \
  --promote-failures /tmp/agentguard-fuzz-promotions \
  --promotion-format patch \
  --allow-fuzz-failures \
  --force
```

Promotion packages include minimized variant metadata, a minimal fixture repo or
unified patch, an expected contract fragment, a reproduction command, and a
README explaining the failure. Packages avoid raw `.agentguard` artifacts,
absolute local paths, and secrets.

Review promoted regressions manually before copying them into permanent
benchmarks. Maintainers should inspect the reduced inputs, confirm the expected
check behavior, choose stable benchmark names and config paths, add or update a
contract, and only then edit the registry or suites in a normal code review.
Promotion is manual so transient check quirks or overly narrow synthetic cases
do not silently become permanent corpus commitments.

## Limitations

- Variants synthesize check evidence and do not execute external agents.
- Execution is serialized; `--workers` is preserved as deterministic aggregation
  metadata for compatibility with other benchmark diagnostics.
- Path traversal variants are represented as diff path evidence. Files are
  materialized with sanitized names so the command never writes outside the
  output directory.
- Safe near misses are small templates, not a complete false-positive corpus.
- Minimization preserves the same expectation failure; it is not a semantic
  proof that the smallest possible real-world benchmark has been found.
- Promotion packages are review aids, not automatically registered benchmarks.

## Related Diagnostics

Benchmark contracts validate that registered benchmark families still behave as
designed when executed normally.

Mutation diagnostics apply a versioned catalog of deterministic safe and unsafe
actions to copied fixtures, then run tests, diff collection, checks, and
scoring.

Benchmark fuzzing differs from both: it uses internal generated templates rather
than permanent fixture files or registry contracts, and it focuses on quickly
expanding policy boundary coverage across many small deterministic variants.
