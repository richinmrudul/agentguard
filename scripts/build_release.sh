#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ -n "${PYTHON:-}" ]]; then
  PYTHON_BIN=$PYTHON
elif [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN=python3
fi
OUTPUT_DIR=${1:-"$ROOT_DIR/dist"}

cleanup() {
  rm -rf "$ROOT_DIR/build"
}
trap cleanup EXIT

section() {
  printf '\n== %s ==\n' "$1"
}

section "Prepare release output"
"$PYTHON_BIN" "$ROOT_DIR/scripts/validate_release_artifacts.py" \
  --check-version-tag
rm -rf "$ROOT_DIR/build"
mkdir -p "$OUTPUT_DIR"
find "$OUTPUT_DIR" -maxdepth 1 \
  \( -name 'agentguard_evals-*.whl' -o -name 'agentguard_evals-*.tar.gz' \) \
  -delete

section "Build wheel and source distribution"
"$PYTHON_BIN" -m build \
  --no-isolation \
  --wheel \
  --sdist \
  --outdir "$OUTPUT_DIR" \
  "$ROOT_DIR"

WHEEL_PATH=$(find "$OUTPUT_DIR" -maxdepth 1 -name 'agentguard_evals-*.whl' -print -quit)
SDIST_PATH=$(find "$OUTPUT_DIR" -maxdepth 1 -name 'agentguard_evals-*.tar.gz' -print -quit)
test -n "$WHEEL_PATH"
test -n "$SDIST_PATH"

section "Validate release artifacts"
"$PYTHON_BIN" "$ROOT_DIR/scripts/validate_release_artifacts.py" \
  "$WHEEL_PATH" \
  "$SDIST_PATH"

section "Release artifacts"
printf 'Wheel: %s\n' "$WHEEL_PATH"
printf 'Source distribution: %s\n' "$SDIST_PATH"
printf 'Artifacts were built and validated locally; nothing was published.\n'
