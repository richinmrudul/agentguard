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

## Candidate security decision

The hosted A/B candidate at canonical identity
`sha256:e9caf0f4ce96c6c53d22241b25dc5109960831ecf5e6f64eac7072c3eb3c3ff2`
uses base digest `sha256:ab7db4566f1d345612bcd57e1d33d8beb428d111f477dac98521a98fa4ab754d`.
Both scans report the same 26 HIGH occurrences across the ten CVEs below,
zero CRITICAL, and no scanner-reported fixed version. The Debian source
trackers identify fixes in other releases for several findings; that is not
an installed fixed version in this candidate. No exception is approved or
proposed by this review. The owner for remediation is the AgentGuard
maintainer. There is no approval date. Any later exception would require a
separate explicit decision, with expiry no later than 2026-11-06. A changed
base, Python version, import/call graph, TLS behavior, or provider parsing
path requires a fresh review.

| CVE | Installed binary package and version | Vulnerable component/path and candidate reachability |
| --- | --- | --- |
| [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | `libncursesw6`, `libtinfo6` `6.5+20250216-2` (source `ncurses`) | `infocmp` CLI `analyze_string` overflow. Libraries are present, but `infocmp` is absent and the immutable Python entrypoint cannot invoke it: vulnerable executable path absent. Neither TLS, HTTP, JSON/SSE nor ledger data is passed to a ncurses tool. |
| [CVE-2026-15308](https://security-tracker.debian.org/tracker/CVE-2026-15308) | `libpython3.13-minimal`, `libpython3.13-stdlib`, `python3.13-minimal`, `python3.13-venv` `3.13.5-2+deb13u5` (source `python3.13`) | `html.parser.HTMLParser` incremental-feed CPU denial of service. `html/parser.py` is present. Candidate code uses JSON and SSE, not HTML, but the full transitive import/call path under malformed provider-controlled HTTP has not been proved closed: **potentially reachable for approval purposes**. |
| [CVE-2026-19445](https://security-tracker.debian.org/tracker/CVE-2026-19445) | Same four Python packages/version | Server-side `ssl.SSLContext.sni_callback` context-replacement use-after-free. The agent-facing server is plain HTTP on the internal network; the upstream TLS path is client-only and installs no SNI callback. The documented vulnerable server path is not present in this runtime: present library, demonstrably unreachable call path. |
| [CVE-2026-19553](https://security-tracker.debian.org/tracker/CVE-2026-19553) | Same four Python packages/version | `SSLContext.wrap_bio` without a nonempty `server_hostname` can skip hostname verification. The gateway's only TLS client calls `wrap_socket` with the exact hostname and uses normal CA checking; it does not call `wrap_bio`: present library, demonstrably unreachable vulnerable call path. Wrong-hostname/CA mock tests remain required. |
| [CVE-2026-7210](https://security-tracker.debian.org/tracker/CVE-2026-7210) | Same four Python packages/version | `xml.parsers.expat`/ElementTree hash flooding on crafted XML. `xml/parsers/expat.py` is present; the candidate directly parses JSON/SSE only. Without a complete transitive-path proof for untrusted HTTP/provider data, classify **potentially reachable for approval purposes** rather than inheriting the old gateway exception. The fixed `libexpat1` alone does not fix the Python-side issue. |
| [CVE-2026-82049](https://security-tracker.debian.org/tracker/CVE-2026-82049) | Same four Python packages/version | `tarfile` extraction filters on a crafted hardlink-to-symlink archive. `tarfile.py` is present; runtime code has no archive ingestion or extraction API. A complete transitive call-path proof has not been produced: **potentially reachable for approval purposes**. |
| [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | `libuuid1` `2.41.5-0+deb13u1` (source `util-linux`) | Privileged `mount` helper/post-mount hooks. `libuuid.so` is present, but `mount` and its privileged helper path are absent; non-root gateway has no mount operation. Vulnerable executable path absent. |
| [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | Same `libuuid1` | `nsenter --join-cgroup` retained root file descriptor. `nsenter` is absent and the gateway is non-root: vulnerable executable path absent. |
| [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | Same `libuuid1` | `mount X-mount.subdir` symlink traversal. `mount`, fstab-authorized execution and mount privileges are absent: vulnerable executable path absent. |
| [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | Same `libuuid1` | Restricted bind-mount source race in SUID `mount`. `mount`, SUID execution and mount privileges are absent: vulnerable executable path absent. |

The source import graph includes `http.server`, `http.client`, `ssl`, `json`,
`socket`, `ipaddress`, `fcntl`, and filesystem/ledger operations. The image
still contains `venv`, `ensurepip`, Python test support, `html.parser`, XML,
`tarfile`, ncurses libraries, `libuuid`, and locale tools. Those are inherited
from the pinned distroless base, not required by the explicit entrypoint.
Removing them by ad-hoc file deletion would break package/rootfs integrity
and is not a security fix. The base is shell-, package-manager-, and
compiler-free at runtime, but its broad stdlib/native surface is not bounded
enough for the expanded provider-facing metering role with only 15 days until
the old exception deadline. The preferred next step is a separately reviewed
narrower custom Python runtime or memory-safe compiled gateway; a newer fixed
distroless base can be considered only after its exact digest, dependency set,
mock behavior, and fresh scan are reviewed. None is approved here.
