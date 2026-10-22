# Replacement metering-gateway security candidate

Issue #322 is a security prerequisite for #316, not an image-publication or
live-study approval. The candidate uses a pinned linux/amd64 distroless Python
base and fixed UID/GID `65532:65532`. Its immutable entrypoint is the B1
mock-only gateway: startup requires `STAGE1_B1_MOCK_ONLY=true` and a bound
local-mock configuration. The real credential resolver is present as reviewed
source but its approved replacement-subject set is empty; the entrypoint does
not invoke it. Hosted tests use only internal Docker networks, a local TLS
mock provider, and fake canary values. No public provider or DNS is needed.

The candidate is **not** the earlier gateway image. The previous reviewed
source image had 38 normalized SBOM rows and 26 HIGH occurrences across ten
CVEs, with no CRITICAL or fixable HIGH/CRITICAL. Its exception manifest binds
the earlier canonical identity and expires 2026-11-06. Neither that identity
nor those exceptions approve the metering gateway's expanded TLS, HTTP, and
ledger behavior. A change in gateway identity or runtime imports requires a
new exact reachability review.

The `model-compatibility` CI job builds the candidate twice with `--no-cache`
from the same exact source commit and pinned base. It saves both image archives,
Docker inspections, normalized rootfs inventories, canonical identities,
original and normalized Syft SBOMs, package-license inventories, raw Trivy
JSON, normalized findings, scanner/database metadata, source/build/capability
hashes, and `SHA256SUMS`. The two builds must agree on rootfs, runtime config,
canonical identity, SBOM rows, licenses, and HIGH/CRITICAL finding set. The
same job runs the patched Codex candidate through this gateway image and the
repository-controlled TLS mock with the shared ledger. Raw evidence uploads
with `always()` before the policy step fails on any unreviewed HIGH or CRITICAL.

Review order is fixable findings, unnecessary components, then each remaining
finding against its exact file/package/version and the new call paths.
In particular, evaluate provider-controlled TLS, HTTP headers and bodies,
SSE/JSON, DNS answers, policy files, and ledger data before claiming a
library is unreachable. A package's mere lack of direct import is insufficient.
No wildcard or old-image exception is permitted. A bounded exception proposal
must name every CVE, package/version, base and candidate identity, reachable
function, exploit prerequisites, controls, owner, and an expiry no later than
2026-11-06. The candidate PR must remain a draft until that review or a
remediation/runtime redesign is complete.

The approved older GHCR images remain valid only for their original
mock/application-containment scope. No image, tag, registry package, live
profile, authorization, provider credential, or study is created here.
