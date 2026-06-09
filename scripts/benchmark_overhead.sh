#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ITERATIONS="${1:-10}"
OUTPUT="${2:-/tmp/agentguard-overhead-$(date -u +%Y%m%dT%H%M%SZ).json}"
PYTHON="${AGENTGUARD_PYTHON:-${REPO_ROOT}/.venv/bin/python}"
CONFIG="${REPO_ROOT}/examples/configs/fix_auth_bug.yaml"

if [[ ! -x "${PYTHON}" ]]; then
  echo "Python executable not found: ${PYTHON}" >&2
  exit 2
fi

cd "${REPO_ROOT}"
exec "${PYTHON}" -m agentguard.cli.main benchmark-overhead \
  --config "${CONFIG}" \
  --agent mock-safe \
  --iterations "${ITERATIONS}" \
  --warmups 2 \
  --output "${OUTPUT}"
