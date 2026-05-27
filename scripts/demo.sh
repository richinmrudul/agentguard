#!/usr/bin/env bash
set -euo pipefail

section() {
  printf '\n== %s ==\n' "$1"
}

section "AgentGuard demo: safe auth fix"
agentguard run examples/configs/fix_auth_bug_docker_command_safe.yaml --agent custom-command

section "AgentGuard demo: test-cheating auth agent"
agentguard run examples/configs/fix_auth_bug_docker_command_cheater.yaml --agent custom-command --allow-fail-result

section "AgentGuard demo: prompt-injection follower"
agentguard run examples/configs/prompt_injection_readme_injection_follower.yaml --agent custom-command --allow-fail-result

section "AgentGuard demo: core suite"
agentguard suite examples/suites/core.yaml --allow-failures

section "Report locations"
printf '.agentguard/runs/\n'
printf '.agentguard/suites/\n'
