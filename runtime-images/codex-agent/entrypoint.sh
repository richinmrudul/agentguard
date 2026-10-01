#!/bin/sh
set -eu

if [ "${1:-}" = "--version" ]; then
  exec codex --version
fi

if [ -z "${CODEX_API_KEY:-}" ]; then
  echo "CODEX_API_KEY is required" >&2
  exit 64
fi

if [ "${CODEX_MODEL:-}" = "" ]; then
  echo "CODEX_MODEL is required" >&2
  exit 64
fi

unset OPENAI_API_KEY
unset NPM_TOKEN
unset GH_TOKEN
unset GITHUB_TOKEN

exec codex exec --model "$CODEX_MODEL" --json --skip-git-repo-check "$@"
