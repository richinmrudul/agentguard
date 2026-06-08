#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/agentguard-package-smoke.XXXXXX")
VENV_DIR="$TMP_ROOT/venv"
DIST_DIR="$TMP_ROOT/dist"
WORK_DIR="$TMP_ROOT/work"

cleanup() {
  rm -rf "$TMP_ROOT"
  rm -rf "$ROOT_DIR/build"
}
trap cleanup EXIT

section() {
  printf '\n== %s ==\n' "$1"
}

section "Create isolated virtual environment"
python3 -m venv "$VENV_DIR"
PYTHON="$VENV_DIR/bin/python"
AGENTGUARD="$VENV_DIR/bin/agentguard"
mkdir -p "$DIST_DIR" "$WORK_DIR"

section "Install build frontend"
"$PYTHON" -m pip install build "setuptools>=68"

section "Build wheel and source distribution"
"$PYTHON" -m build \
  --no-isolation \
  --wheel \
  --sdist \
  --outdir "$DIST_DIR" \
  "$ROOT_DIR"
WHEEL_PATH=$(find "$DIST_DIR" -maxdepth 1 -name 'agentguard-*.whl' -print -quit)
SDIST_PATH=$(find "$DIST_DIR" -maxdepth 1 -name 'agentguard-*.tar.gz' -print -quit)
test -n "$WHEEL_PATH"
test -n "$SDIST_PATH"

section "Install wheel"
"$PYTHON" -m pip install "$WHEEL_PATH"

section "Verify installed package isolation"
(
  cd "$WORK_DIR"
  "$PYTHON" - <<'PY'
from pathlib import Path
import sys

import agentguard

module_path = Path(agentguard.__file__).resolve()
venv_path = Path(sys.prefix).resolve()
print(f"agentguard module path: {module_path}")
if venv_path not in module_path.parents:
    raise SystemExit(f"agentguard imported outside venv: {module_path}")
PY
  if "$AGENTGUARD" benchmarks list; then
    printf 'Expected benchmarks list to require repository examples before copy.\n' >&2
    exit 1
  fi
)

section "Copy repository examples"
cp -R "$ROOT_DIR/examples" "$WORK_DIR/examples"

section "Run installed CLI smoke checks"
(
  cd "$WORK_DIR"
  "$AGENTGUARD" --version
  "$AGENTGUARD" --help
  "$AGENTGUARD" benchmarks list
  "$AGENTGUARD" reports list
  "$AGENTGUARD" run \
    examples/configs/fix_auth_bug_local_command_safe.yaml \
    --agent local-command
  "$AGENTGUARD" history stats
)

section "Package smoke checks passed"
