#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PYTHON_BIN=${PYTHON:-"$ROOT_DIR/.venv/bin/python"}
HTML=false
FULL=false

usage() {
  printf 'Usage: %s [--html] [--full]\n' "$0"
}

while (($#)); do
  case "$1" in
    --html)
      HTML=true
      ;;
    --full)
      FULL=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [[ "$PYTHON_BIN" != */* ]]; then
  if ! PYTHON_BIN=$(command -v "$PYTHON_BIN"); then
    printf 'Python executable not found: %s\n' "${PYTHON:-python}" >&2
    exit 2
  fi
elif [[ ! -x "$PYTHON_BIN" ]]; then
  printf 'Python executable not found: %s\n' "$PYTHON_BIN" >&2
  exit 2
fi

cd "$ROOT_DIR"
mkdir -p coverage

MARKERS="not docker and not package"
if [[ "$FULL" == true ]]; then
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    MARKERS="not package"
    printf 'Docker is available; including Docker-gated tests.\n'
  else
    printf 'Docker is unavailable; running the non-Docker coverage suite.\n' >&2
  fi
fi

FAIL_UNDER=${COVERAGE_FAIL_UNDER:-$(
  "$PYTHON_BIN" -c \
    'import sys; loader = __import__("tomllib" if sys.version_info >= (3, 11) else "tomli"); print(loader.load(open("pyproject.toml", "rb"))["tool"]["coverage"]["report"]["fail_under"])'
)}

"$PYTHON_BIN" -m coverage erase
"$PYTHON_BIN" -m coverage run -m pytest -m "$MARKERS"
"$PYTHON_BIN" -m coverage xml
"$PYTHON_BIN" -m coverage json -o coverage/coverage.json
if [[ "$HTML" == true ]]; then
  "$PYTHON_BIN" -m coverage html
fi

"$PYTHON_BIN" - "$FAIL_UNDER" <<'PY'
import json
import sys

totals = json.load(open("coverage/coverage.json", encoding="utf-8"))["totals"]
statement = totals["covered_lines"] / totals["num_statements"] * 100
branch = totals["covered_branches"] / totals["num_branches"] * 100
print(f"Statement coverage: {statement:.2f}%")
print(f"Branch coverage: {branch:.2f}%")
print(f"Combined coverage threshold: {float(sys.argv[1]):.2f}%")
PY

"$PYTHON_BIN" -m coverage report --fail-under="$FAIL_UNDER"
