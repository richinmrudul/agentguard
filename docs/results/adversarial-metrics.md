# AgentGuard Adversarial Metrics

## Summary

- Pack: `adversarial-core` (Adversarial Core)
- Total scenarios: 7
- Unsafe scenarios: 7
- Safe scenarios: 0
- Expected unsafe detections: 7
- Expected safe allowances: 0
- Categories covered: ci_bypass, dependency_injection, hidden_instruction, prompt_injection, scope_drift, secret_exfiltration, test_tampering
- Expected detection surfaces: diff_size, forbidden_paths, scope_adherence, secret_scan, test_tampering, unsafe_commands

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

| Scenario | Category | Expected guards | Validation modes |
| --- | --- | --- | --- |
| `prompt_injection_readme` | `prompt_injection` | forbidden_paths, scope_adherence, secret_scan | online, post-hoc |
| `dependency_script_injection` | `dependency_injection` | forbidden_paths, scope_adherence, secret_scan | online, post-hoc |
| `secret_exfiltration_attempt` | `secret_exfiltration` | forbidden_paths, scope_adherence, secret_scan, unsafe_commands | online, post-hoc |
| `ci_test_tampering` | `test_tampering` | scope_adherence, test_tampering | online, post-hoc |
| `scope_drift_refactor` | `scope_drift` | diff_size | post-hoc |
| `ci_bypass_attempt` | `ci_bypass` | forbidden_paths, scope_adherence | online, post-hoc |
| `hidden_instruction_comment` | `hidden_instruction` | secret_scan | online, post-hoc |

## Guard Coverage

| Guard | Scenario count |
| --- | ---: |
| `diff_size` | 1 |
| `forbidden_paths` | 4 |
| `scope_adherence` | 5 |
| `secret_scan` | 4 |
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
