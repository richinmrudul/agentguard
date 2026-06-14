#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/agentguard-resume-demo.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/suite.yaml" <<EOF
suite_id: resume_demo
description: Deterministic checkpoint and resume smoke test.
runs:
  - config: $ROOT/examples/configs/fix_auth_bug.yaml
    agent: mock-safe
EOF

WORK="$WORK" "$ROOT/.venv/bin/python" - <<'PY'
import json
import os
from pathlib import Path

from agentguard.core.matrix import run_matrix
from agentguard.core.matrix_checkpoint import load_checkpoint

work = Path(os.environ["WORK"])
suite = work / "suite.yaml"
checkpoint = work / "checkpoint.json"
matrices = work / "matrices"

try:
    run_matrix(
        suite,
        trials=4,
        workers=1,
        matrices_root=matrices,
        checkpoint_path=checkpoint,
        _interrupt_after_attempts=2,
    )
except KeyboardInterrupt:
    pass
else:
    raise SystemExit("demo matrix did not interrupt")

interrupted = load_checkpoint(checkpoint)
completed_before = sum(
    attempt.status == "completed" for attempt in interrupted.attempts
)
print(f"checkpoint status after interruption: {interrupted.status}")
print(f"completed before interruption: {completed_before}")

result = run_matrix(
    suite,
    trials=4,
    workers=2,
    matrices_root=matrices,
    resume_path=checkpoint,
)
completed = load_checkpoint(checkpoint)
assert completed.status == "completed"
assert result.attempts_reused == completed_before
assert result.attempts_executed_this_invocation == 4 - completed_before
assert [row.trial_index for row in result.runs] == [1, 2, 3, 4]

summary = {
    "planned_attempts": result.attempts_planned,
    "completed_before_interruption": completed_before,
    "reused_attempts": result.attempts_reused,
    "skipped_attempts": result.attempts_skipped,
    "newly_executed_attempts": result.attempts_executed_this_invocation,
    "reuse_percentage": result.reuse_percentage,
    "resume_wall_time_seconds": result.duration_seconds,
    "estimated_recomputation_avoided_seconds": (
        result.estimated_recomputation_avoided_seconds
    ),
}
print(json.dumps(summary, indent=2, sort_keys=True))
print(f"checkpoint status after resume: {completed.status}")
PY
