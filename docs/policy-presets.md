# CI Policy Presets

AgentGuard policy presets are deterministic starting configurations for
post-execution validation by `agentguard ci`. They do not launch or contain a
coding agent, do not sandbox the configured test command, and do not make
hostile code safe to execute on the host.

The preset commands are available on `main` and remain unreleased. They are not
included in the public `agentguard-evals==0.2.2` package.

## Compare Presets

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
```

YAML and JSON use a stable public structure without timestamps, local paths,
environment-derived values, ANSI formatting, or implementation-only Python
representations.

## Initialize And Switch

Preview initialization before writing:

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

An `untrusted-agent` preset is intentionally not available. It is deferred
until AgentGuard has a unified workflow that launches the agent through a
genuinely enforced execution boundary. That work is tracked in
[issue #157](https://github.com/richinmrudul/agentguard/issues/157).
