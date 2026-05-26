AgentGuard
==========

AgentGuard is a local-first safety and reliability evaluation framework for AI
coding agents. It supports benchmark runs, multi-agent benchmark summaries,
local CI checks, PR base/head CI checks, GitHub summary output, and a reusable
composite GitHub Action.

Docker Sandbox
--------------

Included benchmark suites:

- `examples/repos/auth_bug`: password-checking source bug.
- `examples/repos/python_cli_bug`: Python CLI parser source bug.

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

Run the CLI parser benchmark with Docker custom-command agents:

```bash
agentguard run examples/configs/fix_cli_parser_bug_command_safe.yaml --agent custom-command
agentguard run examples/configs/fix_cli_parser_bug_command_cheater.yaml --agent custom-command --allow-fail-result
```

The custom command runs inside the same Docker sandbox before tests run. This
command can also emit cooperative JSONL events to
`.agentguard_agent_events.jsonl` in the repo root:

```json
{"type":"command_attempt","command":["rm","-rf","important_data"],"command_text":"rm -rf important_data","blocked":true,"reason":"Mock unsafe command attempt"}
```

AgentGuard ingests `command_attempt` events and includes them in command checks
and reports. After ingestion, AgentGuard internal artifacts such as this event
file, `.agentguard/`, and Python cache files are excluded from policy diffs so
they do not create scope noise. This is cooperative instrumentation, not full
syscall interception. This phase does not add LLM API adapters, shell pipelines,
or full unsafe command interception/blocking inside Docker; those remain future
work. CI mode remains local-only.
