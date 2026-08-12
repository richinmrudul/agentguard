# Installation and Quickstart

AgentGuard supports Python 3.9, 3.10, 3.11, and 3.12. The product name is
AgentGuard, the production PyPI distribution is `agentguard-evals`, and the
Python import and terminal command remain `agentguard`.

## Install from production PyPI

```bash
python -m pip install agentguard-evals
python -c "import agentguard; print(agentguard.__version__)"
agentguard --version
agentguard --help
```

For an isolated command installation:

```bash
pipx install agentguard-evals
agentguard --version
```

Do not use TestPyPI as an installation source. Its similarly named project is
unrelated to AgentGuard.

## Initialize an existing project

`agentguard init` is included in the production
`agentguard-evals==0.3.0` package. Preview project onboarding before writing
files:

```bash
agentguard init --dry-run --ci github
agentguard init --ci github
```

Continue with [safe project initialization](project-initialization.md) for the
generated-file inventory, conservative Python, Node.js, and Go detection
rules, overwrite model, security boundaries, and first local and CI runs.

## Run a deterministic safe evaluation

The ordinary PyPI package intentionally excludes repository examples. Clone
the repository when you need benchmark fixtures, demo scripts, or committed
result evidence:

```bash
git clone https://github.com/richinmrudul/agentguard.git
cd agentguard
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
agentguard run examples/configs/fix_auth_bug_local_command_safe.yaml --agent local-command
agentguard reports show --latest --type run
```

The fixture is deterministic, local, and network-free. It writes reports,
command evidence, a manifest, and a trace beneath `.agentguard/`, which is
ignored by Git.

Run the curated six-scenario showcase with:

```bash
scripts/showcase_demo.sh
.venv/bin/python scripts/showcase_metrics.py --check
```

Run the broader metadata-backed adversarial foundation with:

```bash
agentguard suite examples/suites/adversarial_core.yaml --allow-failures
.venv/bin/python scripts/adversarial_metrics.py --check
```

`--allow-failures` is intentional: every scenario in the current
`adversarial-core` suite represents expected unsafe behavior.

## Choose an execution boundary

- `custom-command` uses the configured Docker execution path. Docker is
  required only for Docker-backed evaluations.
- `local-command` and `agent-command` execute with host-user permissions and
  are not inherently sandboxed.
- AgentGuard observes configured command/filesystem evidence and applies
  post-hoc policy checks. It is not syscall-level containment or a universal
  security boundary.

Continue with the [demo](demo.md), [benchmark catalog](benchmarks.md), or
[real-agent evaluation guide](evaluation.md).
