# Stage 1 Runtime Images

AgentGuard issue #310 Phase 1 prepares reviewed runtime-image inputs for the
future Stage 1 live-study gateway and Codex CLI agent. Phase 1 does not approve
or publish an image, create a live authorization, use a real credential, contact
an inference API, or start the #294 live study.

## Boundary

The gateway image is an application-level live-study egress component. It is
not an absolute hostile-code sandbox and does not replace the Docker daemon,
host kernel, or maintainer operational boundary. The agent container remains on
an isolated study network and can leave only through the gateway path configured
by #302/#303/#308.

Both images target Linux `amd64` for Stage 1. Runtime execution is expected to
drop capabilities, set `no-new-privileges`, use a read-only root filesystem,
use bounded tmpfs writable paths, apply PID/memory/CPU limits, avoid Docker
sockets, avoid host namespaces, and avoid devices.

## Build Inputs

Gateway:

- Dockerfile: `runtime-images/gateway/Dockerfile`
- Entrypoint: `/usr/bin/python3 /agentguard-live-egress-gateway`
- Base image: `gcr.io/distroless/python3-debian13:nonroot@sha256:339ecee37afe554f5237b9993250bc390ac9f1483a08c9b5e77ac4c016d6d39a`
- Base index digest: `sha256:774595d652a294b54c9bd575b2d9fdd1a4b47547dc17b8bfa4c0e953c64855b3`
- UID/GID: `65532:65532`

Codex agent:

- Dockerfile: `runtime-images/codex-agent/Dockerfile`
- Entrypoint: `/usr/local/bin/agentguard-codex-entrypoint`
- Final base image: `gcr.io/distroless/static-debian12:nonroot@sha256:52dcfbabb7457ea47c82f6e13af8c8a4a1d9f7b0145142b3ecab20f2b888411d`
- Final base index digest: `sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab`
- Builder base image: `node:22.20.0-bookworm-slim@sha256:c385ec44d77c785e2364ac0c9b150809a0fdc17fde3dbf061e3dad07242c6a85`
- Builder base index digest: `sha256:b21fe589dfbe5cc39365d0544b9be3f1f33f55f3c86c87a76ff65a02f8f5848e`
- UID/GID: `10001:10001`
- Package: `@openai/codex`
- Version: `0.159.2`
- Package integrity: `sha512-SE13C3nZCYoVL569BdegoOl6vwjb7o2sXOo7ivwVzaVoY0cswwi0/6pIE0TyO/C0vIkQh3jslExitET7PBTfIg==`
- Linux x64 package: `@openai/codex@0.159.2-linux-x64`
- Linux x64 integrity: `sha512-RrCZ1X52wpa1lOsXtCtSyhjOFdQPh7LH5Ccv8HsKmd/2UXbUwxXFqWXFK3JzatquUNGtW/TLox5Y7qVOGkV0/Q==`
- Credential environment variable name: `CODEX_API_KEY`

The official npm metadata for the package and Linux x64 alias must be
re-verified during build review. Runtime npm/package installation and runtime
update checks are not allowed. The final agent image must carry the verified
Linux x64 Codex musl binary and required Codex helper binaries only; Node, npm,
npm caches, the optional voice library tree, package managers, shells, and
debug utilities are excluded from the final runtime image.

## Mock-Only Validation

Phase 1 validation uses repository-owned mock endpoints and fake canaries only.
It must not use a public inference endpoint, a real provider credential, or a
billable call. Hosted Docker validation must prove the images build from the
reviewed inputs, run as non-root, execute by local digest, and do not push.

The gateway evidence remains bounded and sanitized. Evidence must not contain
URL queries, authorization headers, cookies, request bodies, prompts, model
output, credentials, private paths, or unbounded logs. Missing, malformed,
truncated, contradictory, or incomplete gateway evidence fails closed.

## Usage Evidence

Usage evidence is accepted only when it is attributable to the exact trial and
contains bounded measured token fields. Missing, malformed, conflicting,
incomplete, or unattributable usage prevents the next trial. Estimated cost is
not silently substituted for measured evidence; cost calculation later requires
an explicitly frozen pricing-policy input bound by authorization.

If the exact CLI/protocol cannot provide reliable usage in hosted mock
validation, the status is `USAGE_EVIDENCE_BLOCKED`, images must not be
published, and #294 remains blocked.

## Supply Chain Evidence

Phase 1 tooling records or validates:

- OCI image/layout identity;
- image config and manifest digest placeholders for local/CI artifacts;
- immutable base-image digests;
- source commit identity;
- Dockerfile/build-context digests;
- Codex package integrity evidence;
- SBOM, provenance, license, vulnerability, and secret-scan artifact digests;
- deterministic or explainably reproducible build metadata;
- vulnerability policy status; Phase 1 validation must not claim zero
  high/critical findings unless an actual reviewed scanner artifact produced
  that result.

Scanner failures must not be suppressed. Raw machine-readable scan artifacts
are retained as bounded CI artifacts.


## Temporary Gateway Vulnerability Exceptions

The reviewed Phase 1 gateway image carries 26 HIGH Trivy occurrences that
deduplicate to 13 CVEs. The Codex agent image remains at zero HIGH and zero
CRITICAL findings. The gateway findings are inherited from the reviewed
`gcr.io/distroless/python3-debian13:nonroot` base image, and the reviewed
Debian package records did not report fixed package versions for those
findings at approval time.

The only accepted exceptions are recorded in
`runtime-images/vulnerability-exceptions.json`. They are temporary, exact
digest-bound records for gateway image
`sha256:3b4973229f7644c840fa9dee12c291bff2cf9997bcb4d320e29ce10ee5e72852`
and expire on 2026-11-06. They do not apply to the agent image, any other
gateway image digest, any other base-image digest, fixable findings, CRITICAL
findings, new CVEs, changed package versions, or stale findings that no longer
appear in raw Trivy JSON. Any image, base, import, dependency, or runtime
behavior change requires reevaluation.

A narrower Python runtime or a compiled gateway remains the preferred
longer-term remediation. Docker containment, even with non-root execution,
read-only-root compatibility, dropped capabilities, and no-new-privileges, is
application-level containment and must not be treated as an absolute hostile-code
sandbox.

Phase 1 hosted validation also records a canonical runtime identity for each
image. The canonical identity hashes the normalized exported root filesystem and
runtime configuration that affects process execution, while excluding Docker
creation timestamps, image history serialization, and non-runtime provenance
labels that can change across otherwise equivalent builds. Hosted validation
builds each image twice from the same inputs and fails closed unless both
canonical identities, root filesystem digests, runtime configuration digests,
SBOMs, and vulnerability findings match. The Docker local image ID remains
recorded as diagnostic evidence but is not treated as the exception identity.

## Freeze Manifest

`agentguard.evaluation.runtime_images` defines the strict versioned
`agentguard.stage1-runtime-image-freeze` manifest. Phase 1 may record local and
CI OCI digests plus publication placeholders. It must not claim that images are
published or registry-verifiable.

Final published references and registry manifest digests are filled and
independently verified only in the separately approved Phase 2 publication.

## Publication Gate

The prepared workflow is `.github/workflows/stage1-runtime-images-publish.yml`.
It is `workflow_dispatch` only and requires:

- exact reviewed source commit input;
- approval phrase `APPROVE_STAGE1_RUNTIME_IMAGE_PUBLICATION`;
- maintainer approval to run the workflow;
- repository settings and GHCR namespace permissions that allow package
  publication;
- `contents: read` and `packages: write` only.

Do not dispatch this workflow during Phase 1. Do not change package visibility,
repository settings, environments, protections, secrets, milestones, Pages,
tags, releases, PyPI/TestPyPI, or GHCR administration as part of Phase 1.
