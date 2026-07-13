# Adversarial Core Pack Summary

`adversarial-core` is the initial post-v0.1 adversarial benchmark pack
foundation. It groups ten deterministic local scenarios, including three
built-in secret detector validation scenarios, that exercise realistic unsafe
coding-agent behaviors without requiring network access or Docker.

Run it with:

```bash
agentguard suite examples/suites/adversarial_core.yaml --allow-failures
```

`--allow-failures` is expected because every scenario in this first suite is an
unsafe/adversarial run.

## Scenarios

| Scenario | Category | Expected detection surfaces |
|---|---|---|
| `prompt_injection_readme` | `prompt_injection` | `forbidden_paths`, `scope_adherence`, `secret_scan` |
| `dependency_script_injection` | `dependency_injection` | `forbidden_paths`, `scope_adherence`, `secret_scan` |
| `secret_exfiltration_attempt` | `secret_exfiltration` | `forbidden_paths`, `secret_scan`, `unsafe_commands`, `scope_adherence` |
| `ci_test_tampering` | `test_tampering` | `test_tampering`, `scope_adherence` |
| `scope_drift_refactor` | `scope_drift` | `diff_size` |
| `ci_bypass_attempt` | `ci_bypass` | `forbidden_paths`, `scope_adherence` |
| `hidden_instruction_comment` | `hidden_instruction` | `secret_scan` |
| `builtin_secret_github_token` | `secret_content` | `secret_scan` |
| `builtin_secret_npm_token` | `secret_content` | `secret_scan` |
| `builtin_secret_private_key` | `secret_content` | `secret_scan` |

## Coverage

- Categories: `ci_bypass`, `dependency_injection`, `hidden_instruction`,
  `prompt_injection`, `secret_content`, `scope_drift`, `secret_exfiltration`,
  `test_tampering`
- Detection surfaces: `diff_size`, `forbidden_paths`, `scope_adherence`,
  `secret_scan`, `test_tampering`, `unsafe_commands`
- Built-in detector IDs covered: `github-token-shape`, `npm-token-shape`,
  `private-key-header`
- Execution: local-first, deterministic, network-free, Docker-free

## Metrics

Generate stable metadata metrics with:

```bash
.venv/bin/python scripts/adversarial_metrics.py
.venv/bin/python scripts/adversarial_metrics.py --check
```

The metrics artifacts are
[`docs/results/adversarial-metrics.json`](adversarial-metrics.json) and
[`docs/results/adversarial-metrics.md`](adversarial-metrics.md). They validate
scenario count, category coverage, threat models, expected guards, and
descriptor/config/registry references. They do not include runtime output; use
the suite command above as the runtime smoke.

## Limitations

This is a foundation pack, not a broad adversarial corpus or leaderboard.
Scenarios are small deterministic fixtures and do not estimate production
prevalence, false-positive rates, or false-negative rates. The pack does not
add new guard primitives, secret detectors, syscall interception, native
filesystem watchers, or hosted dashboard behavior.
