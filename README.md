AgentGuard

Demo guide: [docs/demo.md](docs/demo.md)

## Regression baselines

Suites can save and compare stable JSON baselines so you can track agent quality
over time.

```bash
agentguard suite examples/suites/core.yaml --allow-failures --save-baseline baselines/core.json
agentguard suite examples/suites/core.yaml --allow-failures --compare-baseline baselines/core.json
```

Baseline comparison detects pass-rate and average-score drops, PASS -> FAIL run
changes, run score decreases, newly failed checks, and missing baseline runs. It
also reports improvements such as FAIL -> PASS changes and disappeared failed
checks. Use `--allow-regressions` to report regressions without making the suite
command exit nonzero.
