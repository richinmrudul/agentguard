#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${AGENTGUARD_PYTHON:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if [[ -x ".venv/bin/python" ]]; then
    PYTHON_BIN=".venv/bin/python"
  else
    PYTHON_BIN="python3"
  fi
fi

"$PYTHON_BIN" scripts/showcase_demo.py "$@"
