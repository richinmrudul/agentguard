# GitHub Pages Deployment Verification

This versioned record documents the initial public deployment of the AgentGuard
documentation site after the Phase 43A documentation foundation was merged. It
records repository and public-site state observed on 2026-08-01; it is not a
continuous availability guarantee.

- Site: <https://richinmrudul.github.io/agentguard/>
- Source branch: `main`
- Source commit: `1da1431b9081fd292c786b74a5c527d229144497`
- [Documentation workflow run](https://github.com/richinmrudul/agentguard/actions/runs/30705834800)
- Successful run attempt: 2
- GitHub deployment ID: `5705873153`
- Deployment environment: `github-pages`

## Enablement and recovery

The workflow's first attempt failed in `actions/configure-pages` because the
repository did not yet have a Pages site. The strict MkDocs build had already
passed; no Pages artifact was uploaded and the deploy job was skipped. GitHub
Pages was then enabled through the repository API with `build_type: workflow`.
The failed jobs were rerun without changing the workflow or documentation.

Attempt 2 built from the same source commit, configured Pages, uploaded the
exact `site/` artifact, and deployed it successfully. Pages uses HTTPS, has no
custom domain, and deploys through the `github-pages` environment. The legacy
branch deployment path and `mkdocs gh-deploy` are not used.

## Public verification

After deployment:

- the public homepage and sitemap returned HTTP 200 over HTTPS;
- every one of the 41 URLs listed in the sitemap returned HTTP 200;
- the homepage, quickstart, demo, architecture, benchmarks, online guard,
  reports and CI exports, static report sites, release process, and hosted
  documentation pages rendered with the expected titles and primary headings;
- those representative pages had no broken images or horizontal overflow;
- the homepage also had no horizontal overflow at a 390 by 844 viewport;
- code-copy controls produced visible copied-to-clipboard feedback; and
- browser inspection reported no console warnings or errors.

The deployed documentation is separate from the product's
`agentguard reports site` output. The Pages workflow does not publish Python
packages, contact PyPI or TestPyPI, or render uncommitted `.agentguard` runtime
content.

## Scope

Enabling Pages changed the repository's Pages state and automatically created
the `github-pages` deployment environment. No custom domain, repository secret,
package version, tag, release, PyPI state, TestPyPI state, publishing workflow,
or publishing environment was changed. The documentation deployment workflow
retains its existing permissions and immutable Action pins.
