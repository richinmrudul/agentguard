#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/agentguard-package-smoke.XXXXXX")
VENV_DIR="$TMP_ROOT/venv"
DIST_DIR="$TMP_ROOT/dist"
WORK_DIR="$TMP_ROOT/work"
PREBUILT_DIST_DIR=${1:-}
BASE_PYTHON=${PYTHON:-python3}
TOOLCHAIN_LOCK="$ROOT_DIR/requirements/release-build-toolchain.txt"

cleanup() {
  rm -rf "$TMP_ROOT"
  rm -rf "$ROOT_DIR/build"
}
trap cleanup EXIT

section() {
  printf '\n== %s ==\n' "$1"
}

section "Create isolated virtual environment"
"$BASE_PYTHON" -m venv "$VENV_DIR"
PYTHON="$VENV_DIR/bin/python"
AGENTGUARD="$VENV_DIR/bin/agentguard"
mkdir -p "$DIST_DIR" "$WORK_DIR"

if [[ -n "$PREBUILT_DIST_DIR" ]]; then
  section "Use prebuilt wheel and source distribution"
  PREBUILT_DIST_DIR=$(cd "$PREBUILT_DIST_DIR" && pwd)
  find "$PREBUILT_DIST_DIR" -maxdepth 1 \
    \( -name 'agentguard_evals-*.whl' -o -name 'agentguard_evals-*.tar.gz' \) \
    -exec cp {} "$DIST_DIR/" \;
else
  section "Install locked build toolchain"
  "$PYTHON" "$ROOT_DIR/scripts/validate_release_toolchain.py"
  "$PYTHON" -m pip install --disable-pip-version-check \
    --require-hashes \
    --only-binary=:all: \
    -r "$TOOLCHAIN_LOCK"
  "$PYTHON" "$ROOT_DIR/scripts/validate_release_toolchain.py" \
    --check-installed \
    --emit-evidence "$DIST_DIR/release-build-toolchain.json"

  section "Build wheel and source distribution"
  "$PYTHON" -m build \
    --no-isolation \
    --wheel \
    --sdist \
    --outdir "$DIST_DIR" \
    "$ROOT_DIR"
fi
WHEEL_PATH=$(find "$DIST_DIR" -maxdepth 1 -name 'agentguard_evals-*.whl' -print -quit)
SDIST_PATH=$(find "$DIST_DIR" -maxdepth 1 -name 'agentguard_evals-*.tar.gz' -print -quit)
test -n "$WHEEL_PATH"
test -n "$SDIST_PATH"

section "Validate wheel and source distribution"
"$PYTHON" "$ROOT_DIR/scripts/validate_release_artifacts.py" \
  "$WHEEL_PATH" \
  "$SDIST_PATH"

section "Install wheel"
"$PYTHON" -m pip install "$WHEEL_PATH"

section "Verify installed distribution metadata"
"$PYTHON" - <<'PY'
from importlib.metadata import PackageNotFoundError, distribution

installed = distribution("agentguard-evals")
if installed.metadata["Name"] != "agentguard-evals":
    raise SystemExit(
        f"unexpected distribution name: {installed.metadata['Name']!r}"
    )
if installed.version != "0.3.1":
    raise SystemExit(f"unexpected distribution version: {installed.version!r}")
try:
    distribution("agentguard")
except PackageNotFoundError:
    pass
else:
    raise SystemExit("legacy agentguard distribution metadata is installed")
PY

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
  "$AGENTGUARD" presets list
  "$AGENTGUARD" presets show recommended --format json
  "$AGENTGUARD" benchmarks list
  "$AGENTGUARD" reports list
  "$AGENTGUARD" run \
    examples/configs/fix_auth_bug_local_command_safe.yaml \
    --agent local-command
  "$AGENTGUARD" history stats
)

section "Package smoke checks passed"
