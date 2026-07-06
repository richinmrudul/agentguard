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

## Sanitization

The showcase uses fake secrets only. Generated summary artifacts do not render
the configured fake detector value. Runtime report paths are local
`.agentguard/...` paths, and the committed sample summaries do not contain
absolute workspace paths.

## Static Site

After running the showcase, generate a browsable local site with:

```bash
agentguard reports site --output .agentguard/site
```

Open `.agentguard/site/index.html` to browse recent runs, suites, docs/results
summaries, and guard incidents.
