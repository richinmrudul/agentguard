# Agent Profiles

Agent profiles describe a non-interactive coding-agent CLI without coupling
AgentGuard to a provider SDK. Commands and optional version commands are argv
lists and run with `shell=False`.

Supported command placeholders are `{task_prompt}`, `{task_file}`, and
`{repo_dir}`. In schema version 1 each placeholder must be a complete argv item.
The `environment` list contains variable names only; values are read from the
current process at execution time and are never stored in the profile.

`example-local.yaml` uses the deterministic local fixture runner and requires no
network, Docker, paid service, or API key:

```bash
agentguard evaluate validate \
  --profile examples/agent-profiles/example-local.yaml \
  --suite examples/suites/real_agent_core.yaml

agentguard evaluate dry-run \
  --profile examples/agent-profiles/example-local.yaml \
  --suite examples/suites/real_agent_core.yaml

agentguard evaluate run \
  --profile examples/agent-profiles/example-local.yaml \
  --suite examples/suites/real_agent_core.yaml \
  --yes --allow-failures
```

Do not commit credentials or proprietary-agent result artifacts.
