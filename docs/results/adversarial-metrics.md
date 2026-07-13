# AgentGuard Adversarial Metrics

## Summary

- Pack: `adversarial-core` (Adversarial Core)
- Total scenarios: 10
- Unsafe scenarios: 10
- Safe scenarios: 0
- Expected unsafe detections: 10
- Expected safe allowances: 0
- Categories covered: ci_bypass, dependency_injection, hidden_instruction, prompt_injection, scope_drift, secret_content, secret_exfiltration, test_tampering
- Expected detection surfaces: diff_size, forbidden_paths, scope_adherence, secret_scan, test_tampering, unsafe_commands
- Built-in detector coverage: github-token-shape, npm-token-shape, private-key-header

## Validation Mode

- Primary artifact: metadata validation
- Runtime validation in this artifact: false
- Runtime smoke command: `agentguard suite examples/suites/adversarial_core.yaml --allow-failures`

## How To Run

```bash
agentguard suite examples/suites/adversarial_core.yaml --allow-failures
.venv/bin/python scripts/adversarial_metrics.py
.venv/bin/python scripts/adversarial_metrics.py --check
```

## Scenario Coverage

| Scenario | Category | Expected guards | Built-in detectors | Validation modes |
| --- | --- | --- | --- | --- |
| `prompt_injection_readme` | `prompt_injection` | forbidden_paths, scope_adherence, secret_scan | none | online, post-hoc |
| `dependency_script_injection` | `dependency_injection` | forbidden_paths, scope_adherence, secret_scan | none | online, post-hoc |
| `secret_exfiltration_attempt` | `secret_exfiltration` | forbidden_paths, scope_adherence, secret_scan, unsafe_commands | none | online, post-hoc |
| `ci_test_tampering` | `test_tampering` | scope_adherence, test_tampering | none | online, post-hoc |
| `scope_drift_refactor` | `scope_drift` | diff_size | none | post-hoc |
| `ci_bypass_attempt` | `ci_bypass` | forbidden_paths, scope_adherence | none | online, post-hoc |
| `hidden_instruction_comment` | `hidden_instruction` | secret_scan | none | online, post-hoc |
| `builtin_secret_github_token` | `secret_content` | secret_scan | github-token-shape | online, post-hoc |
| `builtin_secret_npm_token` | `secret_content` | secret_scan | npm-token-shape | online, post-hoc |
| `builtin_secret_private_key` | `secret_content` | secret_scan | private-key-header | online, post-hoc |

## Built-In Detector Coverage

| Detector | Scenario count |
| --- | ---: |
| `github-token-shape` | 1 |
| `npm-token-shape` | 1 |
| `private-key-header` | 1 |

## Guard Coverage

| Guard | Scenario count |
| --- | ---: |
| `diff_size` | 1 |
| `forbidden_paths` | 4 |
| `scope_adherence` | 5 |
| `secret_scan` | 7 |
| `test_tampering` | 1 |
| `unsafe_commands` | 1 |

## Sanitization

- Metrics artifacts use repo-relative paths and sanitized category/check IDs.
- Metrics artifacts omit fake secret values, raw diffs, command logs, environment variables, generated `.agentguard` output, and absolute workspace paths.

## Limitations

- Initial foundation only; it is not a broad adversarial corpus.
- Scenarios are deterministic local fixtures, not statistical measurements of production agent behavior.
- Detection depends on configured policies and guard settings.
- The pack does not add new guard primitives, secret detectors, syscall interception, or native filesystem watchers.
