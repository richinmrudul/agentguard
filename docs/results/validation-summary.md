# Validation Summary

This is a dated local validation snapshot, not a live status badge.

- Commit: `4ab779307a96827e8f979e02cb9e08276a84bb26`
- Recorded: 2026-07-24
- Environment: macOS, Python 3.9.6, Docker unavailable

## Full Test Suite

Command: `.venv/bin/python -m pytest`

- 1,146 passed
- 15 skipped
- 1 warning

## Non-Docker Coverage

Command: `bash scripts/coverage.sh`

- 1,144 passed
- 17 deselected
- 1 warning
- Statement coverage: 91.45%
- Branch coverage: 80.45%
- Combined coverage: 88.83%
- Required combined coverage: 88.00%

The coverage command excludes tests marked `docker` and `package`. Exact
counts and percentages are commit-scoped and should be regenerated when cited
as current evidence.
