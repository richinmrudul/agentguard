AgentGuard
==========

AgentGuard is a local-first safety and reliability evaluation framework for AI
coding agents. It supports benchmark runs, multi-agent benchmark summaries,
local CI checks, PR base/head CI checks, GitHub summary output, and a reusable
composite GitHub Action.

Docker Sandbox
--------------

Benchmark configs can run tests locally or inside Docker:

```yaml
sandbox:
  type: local
```

```yaml
sandbox:
  type: docker
  image: python:3.11-slim
  workdir: /workspace
  network: none
  timeout_seconds: 60
```

AgentGuard mounts the copied benchmark repository into the Docker container,
runs `python -m pip install --no-build-isolation -e .`, and runs the configured
`test_command` inside the container. Diff collection and policy checks still
happen on the host.

Run tests in Docker with a host-side mock agent:

```bash
agentguard run examples/configs/fix_auth_bug_docker.yaml --agent mock-safe
```

Phase 4B also supports a Docker-only custom command agent. Add an
`agent_command` and run with `--agent custom-command`:

```yaml
agent_command: python agent_scripts/safe_agent.py
```

```bash
agentguard run examples/configs/fix_auth_bug_docker_command_safe.yaml --agent custom-command
```

The custom command runs inside the same Docker sandbox before tests run. This
phase does not add LLM API adapters, shell pipelines, or full unsafe command
interception/blocking inside Docker; those remain future work. CI mode remains
local-only.
