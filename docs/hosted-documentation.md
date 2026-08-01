# Hosted Documentation

This MkDocs site publishes AgentGuard's maintained project documentation. It
is separate from the product's `agentguard reports site` command, which creates
sanitized static snapshots of local evaluation artifacts.

## Build locally

Documentation tooling is isolated from AgentGuard's runtime dependencies:

```bash
python -m pip install -e ".[docs]"
python -m mkdocs build --strict
python -m mkdocs serve
```

The generated `site/` directory is ignored and must not be committed.
Architecture diagrams use the pinned Mermaid 11.16.0 browser renderer; the
documentation build itself remains Python-only and requires no Node.js toolchain.

## GitHub Pages workflow

`.github/workflows/docs.yml` performs two distinct operations:

1. Pull requests that change documentation or site configuration install the
   bounded documentation dependencies and run a strict build. They never
   upload or deploy a Pages artifact.
2. Relevant pushes to `main`, or a manual dispatch from `main`, build the site
   once, upload that exact `site/` tree as the `github-pages` artifact, and
   deploy it through the `github-pages` environment.

The workflow defaults to `contents: read`. Only the deploy job receives
`pages: write` and `id-token: write`. It uses no repository secret or
long-lived deployment credential.

## Current deployment

GitHub Pages is enabled with **GitHub Actions** as its build source. The
documentation workflow deploys the exact site artifact built from `main` to:

<https://richinmrudul.github.io/agentguard/>

The first successful deployment used source commit
`1da1431b9081fd292c786b74a5c527d229144497`. The
[deployment evidence](results/github-pages-v0.2.2.md) records the initial
missing-setting failure, the successful rerun, and public verification. No
custom domain is configured.

For a new repository or recovery after Pages is disabled, a repository owner
must open **Settings → Pages** and, under **Build and deployment**, select
**GitHub Actions** as the source. Rerun the failed Documentation workflow jobs
or dispatch `docs.yml` from the exact current `main` commit, then verify the
deployment URL before describing it as live.

## Publishing boundary

The Pages workflow does not build or publish Python distributions, modify
releases, contact PyPI or TestPyPI, or render generated `.agentguard` runtime
content. Existing committed, sanitized evidence under `docs/results/` remains
reachable through contextual documentation links.
