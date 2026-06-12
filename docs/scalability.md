# Matrix Scale and Stress Diagnostics

AgentGuard's matrix stress diagnostic measures bounded scheduler, aggregation,
report-row, and SQLite history behavior using a closed internal synthetic
workload:

```bash
agentguard diagnostics matrix-stress
```

The workload does not run Docker, external agents, arbitrary commands, network
requests, or paid APIs. Its attempts are lightweight and sleep-dominated so the
study measures matrix coordination rather than repository copying or coding
work.

Synthetic attempts per second must not be presented as real coding-agent
throughput.

## Methodology

For every selected attempt count, worker count, and repetition, the diagnostic:

1. creates stable attempt indices and IDs
2. runs bounded deterministic arithmetic and a configured sleep
3. places optional failures with a deterministic accumulator pattern
4. schedules attempts through the same bounded scheduler used by production
   matrices
5. restores final rows to attempt-index order regardless of completion order
6. writes one lightweight history record per executed attempt to an isolated
   SQLite database
7. aggregates result and reliability totals
8. measures wall-clock and per-attempt duration
9. records peak traced Python allocations with `tracemalloc`
10. validates rows, history IDs, ordering, totals, and fail-fast accounting

The production matrix behavior is not weakened for this benchmark. The shared
scheduler preserves its bounded submission and fail-fast wave semantics.

## Measurements

Each raw repetition records:

- attempts planned, submitted, and executed
- passed and failed totals
- requested and effective workers
- wall-clock duration and attempts per second
- speedup against the matching one-worker repetition
- parallel efficiency, defined as speedup divided by effective workers
- median and nearest-rank p95 attempt duration
- peak traced Python memory
- expected, written, missing, and duplicate history records
- output-order and report-row integrity
- result and reliability total integrity
- stopped-early state, attempts avoided, and estimated time saved

Each attempts/workers cell aggregates minimum, maximum, mean, median, and sample
standard deviation of duration; median throughput, speedup, and efficiency;
maximum traced memory; fail-fast savings; and all integrity findings.

The observed saturation point is the first worker increase where throughput
improves by less than 10% or parallel efficiency falls below 50%. It is
machine- and workload-specific.

## Reproduction

Run the default bounded study:

```bash
agentguard diagnostics matrix-stress \
  --attempts 10,50,100,250 \
  --workers 1,2,4,8 \
  --task-duration-ms 25 \
  --repetitions 3
```

Exercise deterministic failures and fail-fast accounting:

```bash
agentguard diagnostics matrix-stress \
  --attempts 100 \
  --workers 1,4,8 \
  --failure-rate 10 \
  --fail-fast \
  --repetitions 3
```

`--attempts` and `--workers` can be repeated or comma-separated. Worker
selections must include `1` so speedup has a matching baseline.

The default safety caps are:

- maximum attempt count: 5,000
- maximum worker count: 64
- maximum repetitions: 20
- maximum task duration: 1,000 ms
- maximum total planned attempts: 100,000

Use `--unsafe-large-run` only after intentionally reviewing the requested
resource use.

Reports are written under:

```text
.agentguard/diagnostics/matrix-stress/<study-id>/matrix-stress.json
.agentguard/diagnostics/matrix-stress/<study-id>/matrix-stress.md
```

The study directory also contains isolated SQLite history databases used by
the integrity checks. Generated `.agentguard/` artifacts are ignored and should
not be committed.

A sanitized result for the bounded local study is available at
[`docs/results/matrix-scale-summary.json`](results/matrix-scale-summary.json).

## Integrity and Exit Codes

Every non-fail-fast repetition must execute all planned attempts. Every
executed attempt must appear exactly once in ordered report rows and history.
Result and reliability totals must equal executed attempts. Fail-fast requires
`planned >= submitted >= executed`; submitted work is allowed to finish before
the scheduler stops replenishing the queue.

Any integrity failure is retained in raw and aggregate reports and exits 1.
`--allow-study-failures` preserves findings while exiting 0. Invalid options or
unsafe inputs exit 2 without an expected validation traceback.

## Interpretation

Use the diagnostic to compare scheduler scaling across worker counts, identify
machine-specific saturation, verify history completeness under concurrency,
and quantify bounded fail-fast savings for the synthetic workload.

Speedup below the worker count is expected because scheduling, SQLite, report
data, and interpreter overhead remain. Higher traced memory with more workers
can be a reasonable cost of concurrent futures and history writes. Integrity
failures are correctness defects, not performance tradeoffs.

Measured efficiency can exceed 100% because the workload includes sleep and
SQLite operations that overlap under concurrency, and speedup compares matching
wall-clock repetitions. This does not imply superlinear compute performance.

## Limitations

- The workload is synthetic, internal, and sleep-dominated.
- Attempts per second do not estimate coding-agent throughput.
- No repositories are copied and no policy checks or external agents run.
- `tracemalloc` excludes native allocations and is not total process RSS.
- SQLite and filesystem results depend on the local machine.
- Fail-fast time saved is estimated from observed median attempt duration.
- Repetitions characterize variability but do not establish statistical
  significance.
- Saturation depends on the selected sizes, workers, duration, and machine.
