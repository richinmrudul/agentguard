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

## Required one-time repository setting

After the workflow is merged, a repository owner must open **Settings → Pages**
and, under **Build and deployment**, select **GitHub Actions** as the source.
Then run the documentation workflow from `main` if a push build is not already
queued. Verify the deployment and the expected URL:

<https://richinmrudul.github.io/agentguard/>

Until that post-merge deployment succeeds and the URL is verified, repository
documentation must describe the site as configured for GitHub Pages rather
than already live. No custom domain is configured by this repository.

## Publishing boundary

The Pages workflow does not build or publish Python distributions, modify
releases, contact PyPI or TestPyPI, or render generated `.agentguard` runtime
content. Existing committed, sanitized evidence under `docs/results/` remains
reachable through contextual documentation links.
