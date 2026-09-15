# CI Policy Presets

AgentGuard's current source includes three stable CI policy presets for
post-execution validation by `agentguard ci` and one experimental contained-run
preset intended for v0.4.0. The stable CI presets do not launch or contain a
coding agent, do not sandbox the configured test command, and do not make
hostile code safe to execute on the host.

The published production `agentguard-evals==0.3.1` package includes the stable
`minimal`, `recommended`, and `strict` preset commands and ordinary
`agentguard init` / `agentguard ci` workflows. It does not include the
experimental `untrusted-agent` preset. `agentguard init --preset
untrusted-agent` is available in this source after issue #261 and is intended
for a future v0.4.0 release after release preparation.

## Compare Stable CI Presets

| Effective setting | `minimal` | `recommended` (default) | `strict` |
| --- | ---: | ---: | ---: |
| Test-command timeout | 120 seconds | 60 seconds | 30 seconds |
| Captured output bound | 400,000 bytes | 200,000 bytes | 100,000 bytes |
| Expected modified files, maximum | 100 | 50 | 25 |
| Diff files, maximum | 100 | 50 | 25 |
| Added lines, maximum | 4,000 | 2,000 | 1,000 |
| Deleted lines, maximum | 2,000 | 1,000 | 500 |
| Scope finding severity | warning | warning | error |
| Diff-size finding severity | warning | warning | error |
| Built-in content detectors | none | none | GitHub token shape, npm token shape, private-key header |

All presets retain the Phase 44A allowed, forbidden, test, unsafe-command, and
secret-path patterns. They run all seven CI checks. Test failures,
test-tampering findings, forbidden-path findings, unsafe-command findings, and
secret findings retain blocking `error` or `critical` severities. Scope and
diff-size findings are warnings in `minimal` and `recommended`; `strict` makes
them blocking errors.

These are the settings consumed by the current CI path. Presets intentionally
do not emit `sandbox`, Docker, network, resource-container, `command_policy`,
`filesystem_watcher`, agent, or benchmark settings because `agentguard ci`
does not enforce them.

## Intended Use

### `minimal`

Use `minimal` for trusted local experiments and low-risk development where
basic evidence and all mandatory checks are still required, but wider file,
diff, time, and output bounds reduce setup friction. It is not an execution
boundary for untrusted code.

### `recommended`

Use `recommended` for ordinary development and pull-request CI. It is the
default and is byte-for-byte compatible with the Phase 44A generated
configuration when the same project and test-command detection are used:

```bash
agentguard init
agentguard init --preset recommended
```

These commands select the same effective configuration.

### `strict`

Use `strict` for controlled higher-assurance CI gates. It uses tighter bounds,
makes scope and diff-size violations blocking, and opts into three supported
shape-based secret detectors. Review the thresholds and possible detector
findings for the repository before adoption. Detection occurs after changes
exist; strict does not prevent host-side effects during test or agent
execution.

### `untrusted-agent` (experimental for v0.4.0)

Use `untrusted-agent` only with `agentguard contained-run` and an explicit argv
after the literal `--` boundary:

```bash
agentguard init --preset untrusted-agent
agentguard contained-run agentguard.yaml -- AGENT_ARGV
```

This preset generates a contained-run starter config with Docker-backed
application-level containment settings and documented Docker and host trust
assumptions. It is not a broad safety guarantee. Ordinary `agentguard ci`,
`local-command`, `agent-command`, and other uncontained execution paths reject
configs with `contained_execution` before running tests or agents.

Version truthfulness matters: this section describes the current source after
issue #261. Do not read it as a claim that published
`agentguard-evals==0.3.1` contains `untrusted-agent`.

Linux Docker Engine is the supported platform for full contained-run claims.
Docker Desktop is accepted only as `docker-desktop-experimental` with reduced
status after explicit review. The config requires a digest-pinned Docker image,
defaults network to `none`, and exposes no ambient host environment variables
or tokens. Add environment only through explicit
`contained_execution.environment` allowlist entries. Generated placeholders,
including the Docker image, are intentionally explicit and fail safely until a
maintainer replaces them with reviewed project values.

## List And Inspect

List the canonical, case-sensitive preset names:

```bash
agentguard presets list
```

Inspect the intended use, requirements, limitations, and effective settings:

```bash
agentguard presets show recommended
agentguard presets show strict --format yaml
agentguard presets show minimal --format json
agentguard presets show untrusted-agent
```

YAML and JSON use a stable public structure without timestamps, local paths,
environment-derived values, ANSI formatting, or implementation-only Python
representations.

## Initialize And Switch

Preview stable CI initialization before writing:

```bash
agentguard init --preset strict --dry-run --ci github
```

The plan reports the selected preset and exact file actions. Apply it after
review:

```bash
agentguard init --preset strict --ci github
```

The effective settings, rather than decorative preset metadata, are stored in
`agentguard.yaml`. The strict schema has no preset-identity field, so the
initializer does not add one.

Initializing again with the same preset is an idempotent no-op. Selecting a
different preset produces a configuration conflict by default. Review the
planned replacement and use `--force` only when intentionally switching:

```bash
agentguard init --preset strict --dry-run
agentguard init --preset strict --force
```

`--force` can replace only initializer-owned targets. A preset switch does not
duplicate `.gitignore`, rewrite an identical GitHub workflow, or touch unrelated
files.

After generation, customize repository-specific paths, the test command, and
thresholds directly in `agentguard.yaml`. The file remains an ordinary strict
AgentGuard configuration.

For the experimental `untrusted-agent` preset, initialization writes only
`agentguard.yaml` and `.gitignore` by default. It refuses `--ci github` because
that would generate an ordinary uncontained CI workflow. Re-running with the
same generated bytes is an idempotent no-op; non-identical existing files still
conflict unless `--force` is used intentionally.

## Security Boundary

Presets configure test execution bounds, post-execution diff inspection,
policy severities, secret detection, scoring, evidence, and CI exit behavior.
The current CI command runs the configured test command through the host test
runner. It does not launch the coding agent and does not apply the benchmark
orchestrator's Docker, command-guard, or filesystem-watcher controls.

Use least-privilege credentials and an appropriately isolated development or
CI environment. A policy preset is not a security certification and cannot
prevent arbitrary hostile code from affecting the host, reaching resources
available to its process, or exploiting the surrounding platform.

The experimental `untrusted-agent` preset is available only for the contained
runner. It is inspectable through `agentguard presets show untrusted-agent`,
but ordinary CI and uncontained agent modes fail closed when given the generated
contained config.
