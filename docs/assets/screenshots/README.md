# Screenshot source record

The four Phase 43C screenshots were captured on 2026-08-01 from AgentGuard
source commit `150709b3b790aba5c33d1918f00184d46868dd2e`, package version
`0.2.2`. They depict real project surfaces and deterministic local output; no
external coding agent, model API, private repository, or paid service was used.

## Source generation

Equivalent commands from a clean repository checkout are:

```bash
REPO_ROOT="$(git rev-parse --show-toplevel)"
CAPTURE_ROOT="$(mktemp -d)"
cd "$CAPTURE_ROOT"

"$REPO_ROOT/.venv/bin/python" \
  "$REPO_ROOT/scripts/showcase_demo.py" \
  --suite "$REPO_ROOT/examples/showcase/showcase.yaml" \
  --output-dir artifacts/showcase

"$REPO_ROOT/.venv/bin/python" -m agentguard.cli.main run \
  "$REPO_ROOT/examples/showcase/configs/unsafe_command.yaml" \
  --agent local-command --guard-mode audit --allow-fail-result

"$REPO_ROOT/.venv/bin/python" -m agentguard.cli.main reports site \
  --output site \
  --history-db .agentguard/history.db \
  --reports-root .agentguard \
  --title "AgentGuard Evaluation Showcase" \
  --force

python -m http.server --bind 127.0.0.1 8765 --directory site
```

The showcase generated six scenario runs and one suite record: one safe pass
and five expected unsafe failures. The separate audit-mode run generated the
single sanitized guard incident used by the dashboard, incident, and trends
captures. Runtime IDs and timestamps vary between executions.

## Capture inventory

| File | Source | Viewport and crop | Theme |
| --- | --- | --- | --- |
| `agentguard-docs-home.png` | `https://richinmrudul.github.io/agentguard/` | 1440×900 viewport | light |
| `agentguard-dashboard.png` | `site/index.html` | 1440×900 viewport | light |
| `agentguard-incident-detail.png` | generated `site/details/incident-*.html` | 1440 px wide full-page capture; 1055 px high | light |
| `agentguard-evaluation-evidence.png` | `site/trends.html` | 1440×900 viewport | light |

The public homepage was captured from GitHub Pages. The other three images
were captured from the localhost-only server above. Browser and font rendering
can vary, so the screenshots are not claimed to be byte-reproducible.

## Sanitization and optimization

Before capture, the three selected static pages were checked for private or
temporary absolute paths, fake secret literals, authorization values, raw
unsafe-command payloads, raw diffs, and environment assignments. Browser DOM
inspection found none. The public capture contains only intentionally public
repository and release information.

Each image was inspected at full resolution for clipped content, browser or
account chrome, notifications, cursor obstruction, loading state, and sensitive
text. No OCR utility was available, so sanitization combines source-page text
inspection, browser DOM checks, PNG metadata checks, and human visual review;
it does not claim OCR completeness.

The capture backend supplied high-quality browser image bytes. They were
converted to PNG with the platform image utility, then bounded PNG-chunk
inspection removed EXIF and textual metadata chunks. Pixel dimensions were not
resampled. Each file is below 1 MB, and the four-file set is below 3 MB.

Generated `.agentguard`, report-site, and temporary capture trees are not part
of the committed asset set.
