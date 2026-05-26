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

Phase 4A only sandboxes benchmark test execution. The configured mock agent
still modifies the copied benchmark repository on the host, then AgentGuard
mounts that repo into the Docker container, runs
`python -m pip install --no-build-isolation -e .`, and runs the configured
`test_command` inside the container. Diff collection and policy checks still
happen on the host.

Run the Docker example with:

```bash
agentguard run examples/configs/fix_auth_bug_docker.yaml --agent mock-safe
```

Future sandbox phases will move script/custom agent execution into Docker. CI
mode remains local-only in Phase 4A.
