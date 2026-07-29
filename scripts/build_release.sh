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
OUTPUT_DIR="$ROOT_DIR/dist"
VALIDATION_MODE=ordinary-ci

for argument in "$@"; do
  case "$argument" in
    --ordinary-ci)
      VALIDATION_MODE=ordinary-ci
      ;;
    --strict-release-tag)
      VALIDATION_MODE=strict-release
      ;;
    -*)
      printf 'Unknown option: %s\n' "$argument" >&2
      exit 2
      ;;
    *)
      if [[ "$OUTPUT_DIR" != "$ROOT_DIR/dist" ]]; then
        printf 'Only one output directory may be provided.\n' >&2
        exit 2
      fi
      OUTPUT_DIR=$argument
      ;;
  esac
done

cleanup() {
  rm -rf "$ROOT_DIR/build"
}
trap cleanup EXIT

section() {
  printf '\n== %s ==\n' "$1"
}

section "Prepare release output"
if [[ "$VALIDATION_MODE" == strict-release ]]; then
  "$PYTHON_BIN" "$ROOT_DIR/scripts/validate_release_artifacts.py" \
    --strict-release-tag
else
  "$PYTHON_BIN" "$ROOT_DIR/scripts/validate_release_artifacts.py" \
    --ordinary-ci
fi
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
