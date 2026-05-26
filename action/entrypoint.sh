#!/usr/bin/env bash
set -euo pipefail

cmd=(agentguard ci --config "${AGENTGUARD_CONFIG:-agentguard.yaml}")

if [[ -n "${AGENTGUARD_BASE:-}" ]]; then
  cmd+=(--base "$AGENTGUARD_BASE" --head "${AGENTGUARD_HEAD:-HEAD}")
fi

if [[ "${AGENTGUARD_GITHUB_SUMMARY:-true}" == "true" ]]; then
  cmd+=(--github-summary)
fi

if [[ "${AGENTGUARD_ALLOW_FAIL_RESULT:-false}" == "true" ]]; then
  cmd+=(--allow-fail-result)
fi

printf 'Running AgentGuard:'
printf ' %q' "${cmd[@]}"
printf '\n'

exec "${cmd[@]}"
