# Static Report Site

`agentguard reports site` exports a self-contained static HTML report site from
local AgentGuard artifacts. The output can be opened directly from disk or
published as ordinary static files. It does not require a server, build step,
CDN, or external JavaScript/CSS.

## Usage

```bash
agentguard reports site --output /tmp/agentguard-site --force
```

Common options:

```bash
agentguard reports site \
  --output /tmp/agentguard-site \
  --history-db .agentguard/history.db \
  --reports-root .agentguard \
  --include-traces \
  --include-diagnostics \
  --include-results-docs \
  --title "AgentGuard Evaluation" \
  --force
```

The command prints the generated site path and summary counts. Open
`index.html` in the output directory to browse the dashboard.

## Included

The site includes:

- `index.html` dashboard with total records, pass/fail counts, latest runs,
  average score, benchmark/category summaries, reliability summaries when
  matrix data is available, and diagnostic summaries when requested.
- `runs.html`, `suites.html`, `matrices.html`, and `diagnostics.html`.
- `traces.html` when `--include-traces` is set.
- `results.html` when `--include-results-docs` is set and committed
  `docs/results/*.json` or `docs/results/*.md` summaries exist.
- Detail pages for discovered history records, reports, matrices, diagnostics,
  traces, and result documents.
- Matrix detail pages include a `Guard Incidents` section when the matrix JSON
  contains a structured `guard_summary`. It shows the existing aggregate run,
  incident, block, violation, timing-distribution, and per-guard-type values.
- Local `assets/site.css` and `assets/site.js`.

The exporter reads `.agentguard/history.db` and known report locations under
`.agentguard/` by default. Missing history or a missing `.agentguard/`
directory produces a useful empty site.

## Excluded

The exporter does not copy arbitrary files from `.agentguard/`. By default it
does not include raw command stdout/stderr, full diffs, full trace payloads, or
raw command logs. Trace pages are opt-in and show bounded metadata summaries.
Diagnostics and committed result docs are also opt-in.

Corrupt or unreadable individual reports are skipped as data sources and listed
as unavailable instead of failing the whole export.

The site consumes matrix guard aggregates exactly as recorded. It does not
discover incident files, recompute incident statistics, render child incident
evidence, or add standalone incident pages. Matrices without a structured
`guard_summary` continue to render without the section. Missing, partial, or
malformed aggregate fields are displayed as unavailable where appropriate.

## Security And Sanitization

All dynamic HTML content is escaped. Secret-like strings are redacted with
defensive patterns covering common password, token, API key, GitHub token, and
AgentGuard canary formats. Absolute filesystem paths are reduced to safe path
names where possible so generated pages can be shared without leaking local
temporary directories.

The guard section uses a narrow field allowlist. It never renders incident
commands, evidence, child artifact references, or absolute paths, even if
unexpected fields are present in `guard_summary`.

Sanitization is pattern-based and cannot guarantee removal of every possible
secret, encoded value, or application-specific credential. Review the generated
site before publishing outside a trusted environment.

To avoid recursive output capture, the command rejects output paths inside the
configured reports root, such as `.agentguard/site`.

## Publishing To GitHub Pages

Generate the site outside `.agentguard/`, inspect it, then copy or upload the
generated directory contents to the branch or folder used by GitHub Pages:

```bash
agentguard reports site --output /tmp/agentguard-site --include-results-docs --force
```

Publish the files from `/tmp/agentguard-site` using your normal repository
workflow. Do not commit generated site artifacts unless your project explicitly
uses a dedicated Pages branch or artifact repository.

## No Server Required

The generated files are plain HTML, CSS, and tiny local JavaScript for optional
table filtering. Pages remain readable when JavaScript is disabled.
