# Showcase Demo

The showcase is a local, recruiter-friendly demo for the question: "What does
AgentGuard catch?"

Run it from the repository root:

```bash
scripts/showcase_demo.sh
```

It runs six deterministic `local-command` scenarios and writes a compact
detection summary:

```text
.agentguard/showcase/showcase-summary.json
.agentguard/showcase/showcase-summary.md
```

The suite and per-run reports are written under `.agentguard/showcase/suites/`.
The usual run artifacts are generated too: JSON report, Markdown report,
command log, manifest, and trace.

## What It Demonstrates

- A safe source fix is allowed.
- An unsafe command-attempt event is detected.
- A filesystem-boundary escape that writes a secret-like path is detected.
- Test tampering is detected even when tests pass.
- A configured fake secret-content detector catches newly added token-like
  content without rendering the fake token value in summary artifacts.
- A suspicious diff-size/scope-drift scenario is detected.

## Sample Summary

A committed sanitized sample is available at
[`docs/results/showcase-summary.json`](results/showcase-summary.json) and
[`docs/results/showcase-summary.md`](results/showcase-summary.md).

Expected headline:

```text
Scenarios: 6
Safe scenarios allowed: 1
Unsafe scenarios detected: 5
Categories: diff_limit, filesystem_boundary, secret_content, test_tampering, unsafe_command
```

## Metrics

Generate the detection-quality and local overhead metrics from the same
showcase scenarios:

```bash
.venv/bin/python scripts/showcase_metrics.py
```

The command reruns the showcase, measures the safe showcase scenario with the
existing direct-vs-AgentGuard overhead diagnostic, and writes:

```text
docs/results/showcase-metrics.json
docs/results/showcase-metrics.md
```

Current committed metrics report 5/5 unsafe showcase scenarios detected, 1/1
safe scenario allowed, 0 false positives, 0 false negatives, and trace/report
availability for all six scenarios. The timing section is a local showcase
measurement, not a benchmark-grade performance claim.

To run the same proof in GitHub Actions, use
[`examples/github-actions/agentguard-showcase.yml`](../examples/github-actions/agentguard-showcase.yml).
It uploads the committed `docs/results` summaries plus generated
`.agentguard/showcase` JSON/Markdown reports as CI artifacts.

## Showcase Versus Adversarial Core

The showcase is the short polished demo. The post-v0.1 `adversarial-core` pack
is a small evaluation foundation for broader unsafe-agent behaviors, including
prompt injection through repo docs, dependency/script injection, fake
secret-path exfiltration behavior, test tampering, and overbroad scope drift.

Run it with:

```bash
agentguard suite examples/suites/adversarial_core.yaml --allow-failures
```

See
[`docs/results/adversarial-pack-summary.md`](results/adversarial-pack-summary.md)
for the static scenario summary and limitations.

## Sanitization

The showcase uses fake secrets only. Generated summary artifacts do not render
the configured fake detector value. Runtime report paths are local
`.agentguard/...` paths, and the committed sample summaries do not contain
absolute workspace paths.

## Static Site

After running the showcase, generate a browsable local site with:

```bash
agentguard reports site --output /tmp/agentguard-site --include-results-docs --force
```

Open `/tmp/agentguard-site/index.html` to browse recent runs, suites,
docs/results summaries, guard incidents, and the static `trends.html` page.
Trend analytics summarize whatever reports and incident artifacts are present
at generation time, so showcase runs without guard incidents will show the
evaluation records and an empty incident trend state.
