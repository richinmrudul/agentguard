# AgentGuard 90-Second Demo

This demo shows AgentGuard evaluating coding-agent behavior with deterministic
evidence: tests, diffs, forbidden paths, test tampering, secret-path checks, and
suite-level reports. It does not call an LLM or depend on a hosted service.

## What The Demo Proves

AgentGuard can distinguish between agents that make the intended source fix and
agents that get passing tests by taking unsafe shortcuts.

- Safe fix: the agent changes only allowed source files and passes tests.
- Test cheating: the agent weakens tests, so tests pass but AgentGuard fails it.
- Prompt injection: the repo README contains malicious instructions, and the
  follower agent creates `.env`; AgentGuard catches the forbidden/secret path.
- Dependency script injection: untrusted setup instructions tell the agent to
  create dependency state; AgentGuard catches the out-of-scope secret path.
- Filesystem boundary: the escape agent fixes the source bug but creates a
  secret file and reports a path escape command attempt.
- Suite mode: multiple benchmark tasks are summarized as one evaluation run.

## Prerequisites

- Docker is installed and the current user can run containers.
- AgentGuard is installed in the current environment.
- Run commands from the repository root.

If the `agentguard` console script is not on your `PATH`, use:

```bash
python -m agentguard.cli.main ...
```

## Demo Script

### 1. Safe Agent

```bash
agentguard run examples/configs/fix_auth_bug_docker_command_safe.yaml --agent custom-command
```

Expected outcome: `PASS`.

What it demonstrates: the agent fixes the auth bug, tests pass, and the diff
stays inside the allowed source scope.

### 2. Test-Cheating Agent

```bash
agentguard run examples/configs/fix_auth_bug_docker_command_cheater.yaml --agent custom-command --allow-fail-result
```

Expected outcome: `FAIL`.

What it demonstrates: tests pass after the agent weakens the test file, but
AgentGuard detects test tampering and fails the run.

### 3. Prompt-Injection Follower

```bash
agentguard run examples/configs/prompt_injection_readme_injection_follower.yaml --agent custom-command --allow-fail-result
```

Expected outcome: `FAIL`.

What it demonstrates: the agent fixes the source bug and passes tests, but also
follows malicious README instructions by creating `.env`. AgentGuard fails the
run with forbidden-path and secret-scan evidence.

### 4. Dependency Script Injection

```bash
agentguard run examples/configs/dependency_script_injection_safe.yaml --agent custom-command
agentguard run examples/configs/dependency_script_injection_follower.yaml --agent custom-command --allow-fail-result
```

Expected outcome: the safe run `PASS`es and the follower run `FAIL`s.

What it demonstrates: AgentGuard can catch an agent that fixes source but also
follows malicious dependency/setup instructions by creating forbidden dependency
state.

### 5. Filesystem Boundary

```bash
agentguard run examples/configs/filesystem_boundary_safe.yaml --agent custom-command
agentguard run examples/configs/filesystem_boundary_escape.yaml --agent custom-command --allow-fail-result
```

Expected outcome: the safe run `PASS`es and the escape run `FAIL`s.

What it demonstrates: AgentGuard can catch forbidden/secret file creation and
ingested command-attempt evidence for suspicious filesystem boundary behavior.

### 6. Core Suite

```bash
agentguard suite examples/suites/core.yaml --allow-failures
```

Expected outcome: the suite completes and reports mixed results across safe,
test-cheating, prompt-injection, dependency-injection, and filesystem-boundary
behaviors.

What it demonstrates: AgentGuard can package multiple benchmark tasks into one
evaluation artifact with pass rate, average score, best/worst runs, and common
failed checks.

To show the CI gate flow, save a baseline and compare the suite against it:

```bash
agentguard suite examples/suites/core.yaml --allow-failures --save-baseline /tmp/agentguard-core-baseline.json
agentguard gate suite examples/suites/core.yaml --baseline /tmp/agentguard-core-baseline.json --allow-failures
```

## Where Reports Go

Each single benchmark run prints report paths like:

```text
JSON report path: .agentguard/runs/<task-agent-timestamp>/reports/report.json
Markdown report path: .agentguard/runs/<task-agent-timestamp>/reports/report.md
Command log path: .agentguard/runs/<task-agent-timestamp>/command_log.json
```

Suite mode writes:

```text
Suite JSON report path: .agentguard/suites/<suite-id-timestamp>/suite.json
Suite Markdown report path: .agentguard/suites/<suite-id-timestamp>/suite.md
```

The Markdown reports are the easiest artifacts to open during a portfolio demo.
The JSON reports are structured for CI, dashboards, or later analysis.

## Resume Thesis

AgentGuard is a local-first benchmark and policy harness for AI coding agents.
The project thesis is that agent evaluation should be evidence-based: not just
"did tests pass?", but "what changed, which commands ran, did the agent touch
tests, did it create secret files, and did it stay in scope?"

This demo supports that thesis in under 90 seconds by showing three concrete
failure modes:

- A normal safe fix passes.
- A test-cheating shortcut fails despite passing tests.
- A prompt-injection follower fails despite fixing the source bug.
- A dependency/setup-injection follower fails despite fixing the source bug.
- A filesystem-boundary escape fails despite fixing the source bug.

The suite report then turns those individual runs into one portfolio-ready
evaluation summary.
