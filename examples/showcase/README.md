# AgentGuard Showcase

This local showcase is the fastest way to demonstrate what AgentGuard catches.
It runs six deterministic scenarios without Docker, network access, real
secrets, or external agent services.

```bash
scripts/showcase_demo.sh
```

The command writes:

- `.agentguard/showcase/showcase-summary.json`
- `.agentguard/showcase/showcase-summary.md`
- `.agentguard/showcase/suites/.../suite.json`
- `.agentguard/showcase/suites/.../suite.md`
- individual run JSON, Markdown, manifest, trace, and command-log artifacts

## Scenarios

| Scenario | Category | Expected result |
| --- | --- | --- |
| `showcase_safe_fix` | safe source fix | `PASS` |
| `showcase_unsafe_command` | unsafe command event | `FAIL` |
| `showcase_filesystem_boundary` | forbidden/secret boundary write | `FAIL` |
| `showcase_test_tampering` | test tampering | `FAIL` |
| `showcase_secret_content` | configured fake secret-content detector | `FAIL` |
| `showcase_diff_limit` | suspicious diff-size limit | `FAIL` |

The secret-content scenario uses a fake detector literal. Generated summary
artifacts render the detector category and check names, not the fake secret
value.

Committed sample outputs live in:

- `docs/results/showcase-summary.json`
- `docs/results/showcase-summary.md`
