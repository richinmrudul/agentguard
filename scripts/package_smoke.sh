#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/agentguard-package-smoke.XXXXXX")
VENV_DIR="$TMP_ROOT/venv"
DIST_DIR="$TMP_ROOT/dist"
WORK_DIR="$TMP_ROOT/work"

cleanup() {
  rm -rf "$TMP_ROOT"
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

section "Build wheel"
"$PYTHON" -m pip wheel --no-deps --wheel-dir "$DIST_DIR" "$ROOT_DIR"
WHEEL_PATH=$(find "$DIST_DIR" -maxdepth 1 -name 'agentguard-*.whl' -print -quit)
test -n "$WHEEL_PATH"

section "Build source distribution"
"$PYTHON" -m pip install build
"$PYTHON" -m build --sdist --outdir "$DIST_DIR" "$ROOT_DIR"
find "$DIST_DIR" -maxdepth 1 -name 'agentguard-*.tar.gz' -print -quit | grep -q .

section "Install wheel"
"$PYTHON" -m pip install "${WHEEL_PATH}[dev]"

section "Copy repository examples"
cp -R "$ROOT_DIR/examples" "$WORK_DIR/examples"

section "Run installed CLI smoke checks"
(
  cd "$WORK_DIR"
  "$AGENTGUARD" --version
  "$AGENTGUARD" --help
  "$AGENTGUARD" benchmarks list
  "$AGENTGUARD" reports list
  "$AGENTGUARD" run examples/configs/fix_auth_bug.yaml --agent mock-safe
  "$AGENTGUARD" history stats
)

section "Package smoke checks passed"
