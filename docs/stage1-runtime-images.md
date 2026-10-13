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
are retained as bounded CI artifacts. Hosted scan summaries also retain the
Trivy version, vulnerability database schema/version, database update or
download timestamp, and a digest of the retained database metadata when the
scanner cache provides it. Advisory-set drift must fail closed rather than pin
an obsolete database.


## Temporary Gateway Vulnerability Exceptions

The reviewed Phase 1 gateway image carries 31 HIGH Trivy occurrences that
deduplicate to 15 CVEs. The Codex agent image remains at zero HIGH and zero
CRITICAL findings. The gateway findings are inherited from the reviewed
`gcr.io/distroless/python3-debian13:nonroot` base image, and the reviewed
Debian package records did not report fixed package versions for those
findings at approval time.

The only accepted exceptions are recorded in
`runtime-images/vulnerability-exceptions.json`. They are temporary, exact
digest-bound records for gateway canonical identity
`sha256:b30a59331f1b111b6620203d2e25ab8c1cd20a046559ee98d1018d0a5157ac4a`
and expire on 2026-11-06. They do not apply to the agent image, any other
gateway canonical identity, any other base-image digest, fixable findings, CRITICAL
findings, new CVEs, changed package versions, or stale findings that no longer
appear in raw Trivy JSON. Any image, base, import, dependency, or runtime
behavior change requires reevaluation.

`CVE-2026-19445` is accepted only for the exact observed Python 3.13 binary
packages at `3.13.5-2+deb13u5`. Its reviewed vulnerable operation is
server-side `ssl.SSLContext.sni_callback` context switching; the gateway acts
only as an upstream TLS client with `ssl.create_default_context().wrap_socket`
and does not terminate TLS or install an SNI callback.

`CVE-2026-77214` is accepted only for `libexpat1` at
`2.8.3-1~deb13u1`. Its reviewed vulnerable path is Expat `XML_ParseBuffer`
after XML parser-buffer use; the gateway imports no XML parser, performs no XML
or content-type parsing, exposes no XML callback or buffer API, and forwards
provider payloads as bytes after destination authorization.

A narrower Python runtime or a compiled gateway remains the preferred
longer-term remediation. Docker containment, even with non-root execution,
read-only-root compatibility, dropped capabilities, and no-new-privileges, is
application-level containment and must not be treated as an absolute hostile-code
sandbox.

Phase 1 hosted validation also records a canonical runtime identity for each
image. The canonical identity hashes the normalized exported root filesystem and
runtime configuration that affects process execution, while excluding Docker
creation timestamps, image history serialization, layer serialization digests,
and non-runtime provenance labels that can change across otherwise equivalent
builds. Hosted validation builds each image twice from the same inputs and fails
closed unless both canonical identities, root filesystem digests, runtime
configuration digests, SBOMs, and vulnerability findings match. The Docker local
image ID and Docker-reported layer list remain recorded as diagnostic evidence
but are not treated as the exception identity.

## Freeze Manifest

`agentguard.evaluation.runtime_images` defines the strict versioned
`agentguard.stage1-runtime-image-freeze` manifest. Phase 1 may record local and
CI OCI digests plus publication placeholders. It must not claim that images are
published or registry-verifiable.

Final published references and registry manifest digests are filled and
independently verified only in the separately approved Phase 2 publication.

## Build-Once Publication Architecture

The prepared workflow is `.github/workflows/stage1-runtime-images-publish.yml`.
It is `workflow_dispatch` only. It has two jobs:

- `prepare` builds each image exactly once for `linux/amd64`, validates the
  exact built images, exports the exact validated Docker archives, generates
  SBOM and raw Trivy evidence from those archives, applies the reviewed
  vulnerability exception policy, runs mock-only checks, and uploads the
  validated archives plus bounded evidence.
- `publish` depends on `prepare`, downloads those exact archives, verifies
  their manifest/checksum/computed digests before registry authentication, loads
  the archives, pushes the already validated image subjects to GHCR, records
  immutable GHCR digests, rejects any digest recorded in the reviewed
  rejected-publication ledger, pulls by digest, recomputes canonical identities,
  regenerates SBOM and scan evidence, compares canonical SBOM package rows to
  the prepared evidence, reapplies the exception policy with explicit
  pulled-scan role bindings, runs the full local mock egress integration using
  digest references, and only then attests the approved published digest
  subjects.

The `publish` job must not run a Docker build, install packages into an image,
reconstruct an image from source, retag to a moving alias, or publish an
unreviewed platform. The checkout in the protected job is for validation code
only; the image payloads come from the downloaded validated archives.

## Approval Stages And Activation

The workflow remains unusable for publication until a separate explicitly
authorized settings task completes all repository settings. Dispatch requires:

- exact reviewed source commit input;
- approval phrase `APPROVE_STAGE1_RUNTIME_IMAGE_PUBLICATION`;
- trusted `main` branch ref;
- `required_source_commit == github.sha`;
- repository variable `STAGE1_RUNTIME_PUBLICATION_ENABLED` set exactly to
  `true`;
- successful `prepare` job;
- protected environment approval for environment `stage1-runtime-images`.

Do not create or modify that environment or repository variable as part of
runtime-image code review. Before any dispatch, a separate settings task must
create/configure `stage1-runtime-images`, add the required reviewer, disable
administrator bypass if supported by repository policy, restrict deployment to
the trusted `main` branch, and enable `STAGE1_RUNTIME_PUBLICATION_ENABLED`
only for the approved publication window.

If GitHub repository settings cannot guarantee that a missing environment is
protected before first use, operators must verify the environment and branch
deployment protection out of band before dispatch. The activation variable is
an additional fail-closed guard; it is not a substitute for environment
protection.

As of this corrective prerequisite, the protected environment is configured and
the first publication attempt has run once and failed post-push verification.
The pushed first-attempt digests are recorded as rejected and are not approved
for study use. The activation variable is disabled or absent, and any second
publication attempt requires a separate explicit authorization.

## Image Coordinates And External State

Phase 2 publication creates externally visible GHCR package state only after
the protected `publish` job is approved. The intended coordinates are:

- `ghcr.io/richinmrudul/agentguard/stage1-gateway:<full-source-commit>`
- `ghcr.io/richinmrudul/agentguard/stage1-codex-agent:<full-source-commit>`

The full source commit is the final selected trusted `main` commit at dispatch
time, not a shortened SHA and not a hardcoded historical merge commit. The
workflow must not create `latest`, release-channel, shortened-SHA, moving, or
unreviewed platform tags. Future Stage 1 study profiles must use immutable
`@sha256:` GHCR references resolved after publication, not tags.

The external state created by an authorized Phase 2 run is limited to the two
GHCR image packages/tags, their immutable registry digests, registry-bound
attestations for those digests, and retained GitHub Actions evidence artifacts.
No provider credential, live authorization, paid call, public inference API
contact, release, PyPI/TestPyPI publication, or live study is involved.

## Provenance Subjects

Publication evidence records the source repository, exact commit, workflow
file, run ID and attempt, target platform, Dockerfile and build-context
digests, base-image references, Codex package version and integrity, archive
digests, canonical identities, rootfs and runtime configuration digests, SBOM
digests, normalized SBOM package-row digests, package counts, Trivy version
and database metadata, raw scan digests and counts, exception-manifest digest
and expiry, and mock integration status.

SBOM package-row evidence is normalized before hashing. Rows include stable
package identity fields: package type/ecosystem, name, version, PURL when
present, and normalized license identifiers when Syft provides them. Generated
document IDs, timestamps, source paths, location metadata, and cataloger order
are excluded. Rows are sorted deterministically and hashed as canonical JSON.
Post-publication SBOM regeneration must produce the same row count and row
digest for both images; equal counts alone are not sufficient.

GitHub attestations must bind the published GHCR subject names and immutable
registry digests:

- `ghcr.io/richinmrudul/agentguard/stage1-gateway@sha256:...`
- `ghcr.io/richinmrudul/agentguard/stage1-codex-agent@sha256:...`

The local Docker image ID, canonical identity, tag, archive digest, and SBOM
digest are supporting evidence only. They are not the attestation subject.
Attestations are created only after digest pullback, canonical identity
verification, SBOM row comparison, role-bound Trivy policy enforcement, and the
full pulled-by-digest mock integration have all passed. Provenance attestations
for a failed digest prove where that digest came from; they do not mean
AgentGuard approved the digest for study use.

## Pulled-Scan Role Binding

Post-publication Trivy scans must not infer the gateway or agent security role
from a free-form scanner target string. The publish job writes a
machine-readable `scan-bindings.json` file after pullback scans complete. For
each image it binds:

- explicit role, `gateway` or `agent`;
- exact GHCR repository;
- immutable published digest;
- pulled `repository@sha256:...` reference;
- prepared archive role and archive name;
- canonical identity from the publication manifest;
- exact pulled SBOM and Trivy evidence filenames.

The post-publication validator cross-checks those bindings against the
publication manifest and the resolved digest outputs before applying
role-specific vulnerability policy. Gateway findings may use only reviewed
gateway exceptions. Agent findings can never use gateway exceptions. Missing,
unknown, duplicated, swapped, tag-only, repository-mismatched, digest-mismatched,
or basename/substring-only bindings fail closed. Trivy `ArtifactName` and
`Target` formatting differences are tolerated only when they do not assert a
conflicting repository or digest.

## Post-Publication Verification And Failure Behavior

After registry push, verification must pull both images by immutable digest,
recompute canonical identities, require the reviewed gateway and agent
canonical identities, regenerate SBOMs with the reviewed package counts and
canonical package-row digests, rescan with the current Trivy database, reapply
the exact exception policy, and run local-only Docker egress checks using the
pulled digest references.

Before any GHCR login, image load, or push, the publish job performs a triple
archive check: the publication manifest must list exactly
`gateway-image.tar` and `agent-image.tar`; `image-archives.SHA256SUMS` must
list exactly those same two basenames; the manifest digests, checksum-file
digests, and freshly computed archive digests must all agree. Missing,
additional, duplicated, absolute, traversal, symlinked, malformed, oversized,
or role-swapped archive evidence fails closed.

The pulled-by-digest integration uses repository-controlled local Docker
networking only. It requires immutable `@sha256:` gateway and agent
references, verifies non-root users and read-only-root compatibility, runs an
approved local mock destination through the gateway, proves a disallowed
destination and metadata/private destination are denied, verifies a direct
bypass attempt cannot reach the mock provider, checks gateway crash detection,
cleanup, liveness, bounded sanitized evidence, and confirms a fake credential
canary is not retained. The local mock provider is on an internal Docker
network with a documentation-prefix subnet so public internet access and real
provider contact are not required.

Any failure after push fails the workflow, retains evidence, prints the
rejected immutable digest, and requires corrective review. Operators must not
silently overwrite tags, rebuild and retry as if equivalent, delete evidence,
reuse a rejected digest, begin #294 with the failed digest, or claim #310
complete. Automatic package deletion, tag rewriting, and destructive rollback
are intentionally not implemented.

`runtime-images/rejected-publications.json` records immutable digests that were
pushed but rejected by post-publication verification. The first publication
attempt for source commit `26f9c74117185154f81438cdb33922067f92f10d` created
and rejected:

- `ghcr.io/richinmrudul/agentguard/stage1-gateway@sha256:fbe729bf8768fba3c68e4f8ed7eff45eb34ab814745dd7a78a9a65e7e27000a0`
- `ghcr.io/richinmrudul/agentguard/stage1-codex-agent@sha256:07266c6012e9b5d36c295a0ea0d1a7570c97ccbe6332ff8e9d1da1911c496d94`

Those digests remain `eligible_for_study: false` even if a later publication
succeeds. Future publication and study-freeze tooling must reject a candidate
whose immutable digest appears in this file. A second publication attempt
requires a separate read-only readiness check and an explicit publication
authorization; this corrective prerequisite does not dispatch the publication
workflow, mutate GHCR, or approve any digest.
