# Contained Execution Contract

AgentGuard's contained-execution contract defines the threat model for a future
workflow that launches an untrusted coding agent inside a constrained Docker
environment, preserves evidence outside that agent's mounted repository, and
fails before agent startup when required security properties cannot be verified.

This page is authoritative for containment claims. Existing execution modes
remain unchanged by this contract, including current benchmark, Docker,
local-command, and CI modes. The experimental `untrusted-agent` preset is
available only for this contained-run workflow; uncontained execution paths
reject configs with `contained_execution` before running tests or agents.

## Assets And Goals

Protected assets are the host filesystem outside the prepared workspace, host
credentials, CI secrets, the Docker daemon API, network-reachable services,
AgentGuard evidence and reports, benchmark fixtures, test-command integrity,
container image identity, and cleanup/liveness state.

Security goals are to:

- run untrusted agent code with no ambient host network by default;
- expose only the prepared workspace needed for the task;
- keep evidence outside the repository mounted for the untrusted agent;
- prevent the agent from selecting privileged Docker features;
- fail closed before launching the agent when required properties cannot be
  verified; and
- make the remaining trust assumptions and non-goals explicit.

## Trust Boundaries

Trusted components:

- AgentGuard configuration loading, schema validation, orchestration, evidence
  writers, and policy checks;
- the host operating system, host kernel, and local filesystem permissions;
- Linux Docker Engine and its daemon configuration on supported Linux hosts;
- Docker image provenance validation logic once implemented; and
- CI or developer-machine secret management outside the agent container.

The Docker daemon and host kernel are trusted computing base components.
Container escape, malicious Docker daemon behavior, and malicious or vulnerable
host kernels are outside this contract.

Untrusted components:

- the coding agent process, its prompts, tool use, generated commands, and
  self-reported claims;
- the repository under evaluation, including build scripts, dependency hooks,
  tests, hidden instructions, symlinks, and generated files;
- the configured test command and any subprocesses it starts;
- network endpoints reachable from an allowed future network mode; and
- mutable image tags or registry metadata unless resolved to validated immutable
  digest identity.

## Platform Claims

Linux Docker Engine is the authoritative contained-execution platform. A valid
future implementation may make containment claims only after it verifies a
supported Linux Docker Engine environment and the required Docker properties.

Docker Desktop is experimental and carries reduced claims because it inserts a
desktop-managed VM and platform-specific integration layer between the host and
the Linux container runtime. AgentGuard may validate a Docker Desktop planning
configuration, but it must not present Docker Desktop as equivalent to Linux
Docker Engine.

Other platforms, remote Docker daemons, Kubernetes, Podman, and non-Docker
container runtimes are unsupported unless a later contract version explicitly
adds them.

## Required Container Properties

The future contained runner must forbid:

- host networking;
- privileged containers;
- Docker socket mounts;
- host device exposure;
- host PID, IPC, user, UTS, cgroup, or other namespace sharing; and
- evidence directories mounted inside the repository visible to the untrusted
  agent.

The default network mode is `none`. Bridge networking is accepted only as an
explicit v1 opt-in and carries the same prohibition on host namespace sharing,
Docker socket mounts, device exposure, privileged mode, arbitrary Docker flags,
and mutable image identity. Host networking is never allowed.

Images must have validated provenance with immutable digest identity. A mutable
tag alone is not enough for a contained-execution claim.

## Preconditions And Failure

Contained execution must fail before launching the agent when AgentGuard cannot
verify the required platform, Docker daemon settings, image provenance,
workspace mounts, evidence location, network mode, namespace isolation,
privilege mode, device exposure, credential boundary, timeout, or cleanup
supervision.

Failure must happen before the untrusted agent receives credentials, workspace
write access, network access, or a chance to run repository code. A later
cleanup failure may be reported as evidence, but cleanup success is not proof
that no hostile code affected the host.

## Docker Capability Preflight

AgentGuard includes a deterministic Docker containment preflight capability for
the v1 planning contract. The preflight only executes bounded Docker CLI
inspection commands; it does not run the configured agent, the repository test
command, image entrypoints, or repository-controlled commands.

AgentGuard also includes a small least-privilege Docker execution spec renderer
for future contained agents. The renderer takes validated typed fields and emits
a deterministic Docker argv list directly; it does not accept raw Docker flag
strings and does not use shell interpolation. It separates validated
configuration from rendered Docker arguments.

Rendered v1 Docker argv enforces non-root UID/GID execution,
`no-new-privileges`, dropped Linux capabilities, a PID limit, bounded CPU and
memory, a read-only root filesystem, one explicit writable workspace mount or a
bounded tmpfs workspace, bounded tmpfs temporary storage, deterministic
environment ordering, safe AgentGuard-owned container names, and digest-pinned
image references. The renderer has no fields for privileged mode, Docker socket
mounts, device exposure, host PID/IPC/user/network namespace sharing, or
arbitrary user-controlled Docker flags.

The preflight checks Docker CLI availability, daemon availability, bounded
client and server JSON responses, Linux engine identity, Docker Desktop
classification, the selected allowed network, requested resource-limit inputs,
read-only-root and tmpfs API support, digest-pinned local image identity, a
controlled created container inspected by immutable container identity, a
controlled run as the required non-root UID/GID with a bounded writable tmpfs
path, and rejection of prohibited contained-execution options. The controlled
resource probe distinguishes four evidence categories: the resource controls
AgentGuard requested from validated config, whether Docker accepted a created
probe container, the exact configuration Docker exposes through inspection of
that created probe container, and unavailable, ambiguous, malformed, missing,
zero, downgraded, or mismatched evidence. Linux Docker Engine preflight fails
closed when inspection cannot establish the required PID, memory, or CPU
control or adjacent controls including non-root identity, read-only rootfs,
`no-new-privileges`, dropped capabilities, network policy, bounded tmpfs, and
absence of privileged mode, host devices, Docker socket mounts, and host
namespace sharing. AgentGuard does not claim that Docker inspection proves
host-kernel or daemon enforcement beyond those Docker-inspectable container
facts. Probe cleanup removes only the owned probe container by immutable
container identity and verifies post-remove absence; a cleanup failure or
ambiguous liveness check is reported as failed cleanup evidence. Malformed,
missing, contradictory, oversized, timed-out, or unsupported responses fail
closed.

Results are structured as one of:

- `supported`: Linux Docker Engine evidence satisfies the checked v1 boundary
  preconditions.
- `experimental`: Docker Desktop matched an explicit
  `docker-desktop-experimental` plan and carries reduced claims.
- `unavailable`: Docker or required daemon evidence could not be obtained.
- `unsafe`: the configuration or Docker evidence conflicts with the approved
  boundary.

Diagnostics are sanitized and bounded before they are exposed as evidence. They
must not include private paths, credentials, environment values, Docker daemon
endpoints, or unbounded Docker output. This preflight evidence is suitable for
future reports and traces, but broad evidence integration is future work.

## Contained Run Entrypoint

AgentGuard includes an additive public contained-run entrypoint:

```bash
agentguard contained-run agentguard.yaml -- python -m pytest
```

The literal `--` boundary is required. Tokens before that boundary are
AgentGuard CLI arguments; only tokens after it become the contained agent argv.
AgentGuard help flags before the boundary remain AgentGuard CLI help, while
child flags after the boundary, including `--help`, `-h`, repeated flags,
leading-dash arguments, empty-value options, and literal shell metacharacters,
are preserved as structured argv tokens in their original order.
Invocations such as `agentguard contained-run agentguard.yaml python -m pytest`
fail with a controlled usage/configuration error. The argv is passed as a
structured list into the Docker execution spec; AgentGuard does not concatenate
it into a shell string and does not perform shell interpolation.

`contained-run` is opt-in and does not change `run`, `ci`, `benchmark`,
`suite`, `matrix`, local-command, agent-command, or the existing Docker test
runner behavior. It requires a loaded `contained_execution` v1 block plus
`sandbox.type: docker` and a digest-pinned `sandbox.image`. Configuration and
Docker capability preflight run before the contained workspace is prepared or
the agent argv is launched.

At launch time AgentGuard prepares a lifecycle-owned copy of the selected
repository, mounts that prepared workspace as the only writable repository tree,
and keeps AgentGuard evidence outside that mounted repository. The original
repository is not mounted writable. For the v0.4 bind-mounted prepared
workspace, `contained_execution.required_uid` and `required_gid` must match the
current host user so the configured non-root container identity can write only
the lifecycle-owned workspace copy without adding broad world-writable host
permissions. Incompatible UID/GID mappings fail closed before Docker preflight,
workspace preparation, or agent launch. The generated Docker argv comes only
from the validated contained-execution config and typed Docker execution spec.
It uses the configured non-root UID/GID, default `network: none` unless an
explicit validated `bridge` opt-in is present, read-only root filesystem, tmpfs
`/tmp`, capability drop, `no-new-privileges`, PID, memory, and CPU bounds. It
does not provide Docker socket mounts, host devices, host namespaces,
privileged mode, host networking, arbitrary host-path mounts, or arbitrary
Docker flag strings.

The contained process receives no ambient host environment. AgentGuard supplies
only fixed runtime defaults plus explicitly configured allowlist entries:
`PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`,
`HOME=/tmp/agentguard-home`, `LANG=C.UTF-8`, and `LC_ALL=C.UTF-8`. User
configuration cannot override those defaults, and AgentGuard does not forward
the host's `PATH`, `HOME`, locale, Docker client state, credential stores,
runtime sockets, SSH agent sockets, or other host-control path/config/socket
variables.

Allowlisted entries are rendered as structured Docker argv tokens, never as
shell assignment strings, so argument boundaries are preserved. Literal entries
must provide `value`. Host-sourced entries read exactly the named host
environment variable only; optional absent values are omitted deterministically,
and `required: true` values fail before Docker preflight, workspace
preparation, or agent launch. Variable names must match
`^[A-Z_][A-Z0-9_]*$`, are limited to 64 characters, and are rejected when they
duplicate another configured name after normalization. The allowlist is bounded
to 32 configured entries, 4096 characters per value, and 16384 serialized
bytes across configured names and literal values. Names and values reject NUL
and unsafe control characters.

Docker/client/daemon/config variables and host-control/socket/config/path names
are reserved, including `DOCKER_*`, `COMPOSE_*`, `DYLD_*`, `LD_*`, `PATH`,
`HOME`, `LANG`, `LC_ALL`, `SSH_AUTH_SOCK`, `XDG_RUNTIME_DIR`,
`KUBECONFIG`, certificate-bundle variables, and names ending in path, config,
socket, runtime, home, or credential-store suffixes. Secret-like names such as
tokens, passwords, API keys, credentials, auth values, and cookies are allowed
only when the entry is explicit and includes `allow_sensitive: true`; those
values are added to AgentGuard's destination-neutral redaction inputs before
any contained-run evidence is persisted. Public diagnostics, JSON artifacts,
reports, command displays, traces, and result serialization record environment
names and redacted placeholders, not values. Redaction is defensive: Docker
daemon administrators and host users able to inspect a live container or Docker
daemon internals may still observe environment values while the container runs.
AgentGuard does not create a long-lived credential store, token refresh
mechanism, or secret manager.

The host subprocess that invokes Docker keeps only the minimal host `PATH`
needed to find the Docker CLI. A nonzero contained agent exit remains an
agent-command failure unless AgentGuard has specific Docker operational
evidence, such as Docker's launch failure status or a Docker subprocess error.

The command captures bounded stdout, stderr, exit status, timeout state,
workspace mutations, cleanup status, Docker preflight evidence, and a compact
contained-run JSON artifact with sanitized diagnostics. Existing post-execution
policy checks are evaluated against the captured workspace mutation summary
where feasible.

## GitHub Actions Adoption

The maintained GitHub Actions adoption path is intentionally opt-in and
copyable rather than generated by `agentguard init`. See
[`examples/github-actions/agentguard-contained-run.yml`](https://github.com/richinmrudul/agentguard/blob/main/examples/github-actions/agentguard-contained-run.yml)
for a supported Linux Docker runner smoke workflow.

The workflow uses `pull_request`, read-only `contents` permission, immutable
Action pins, checkout with credentials disabled, a hosted Linux Docker runner,
Docker verification before the contained command, a digest-pinned image,
`network: none`, no privileged mode, no host networking, no Docker socket,
no host namespace sharing, no host devices, and no ambient GitHub token or
secret environment forwarding into the container. The deterministic command is
passed after the required `--` boundary as structured argv:

```bash
agentguard contained-run agentguard-contained.yaml -- /bin/true
```

It uploads the hidden evidence path
`.agentguard/contained-runs/*/contained-run.json` with `if: always()`,
`include-hidden-files: true`, `if-no-files-found: error`, and bounded
retention. The artifact path is deliberately narrow and does not upload the
prepared workspace or broader `.agentguard/` tree.

Version wording matters for this adoption path. This source tree remains
`0.3.1`, and v0.4.0 has not been published yet. The copyable workflow uses
`agentguard-evals==0.4.0` as a release-time substitution placeholder for the
future package that contains `contained-run`; do not replace it with
`agentguard-evals==0.3.1`, a mutable branch, or a source checkout when adopting
the maintained workflow.

## Containment Evidence

Contained runs emit the versioned `agentguard.containment-evidence` v1 object.
The same canonical object is used by JSON and Markdown reports, run manifests,
execution traces and replay evidence, JSON history exports, and static-site run
details. Standard local runs record containment as `not_applicable`; the older
Docker test sandbox is identified separately as `docker-sandbox` and is not
presented as the `contained-run` boundary.

The object separates requested intent from observed state. `requested` records
the selected platform, network, image-provenance policy, and sanitized command
and path roles. The `preflight`, `image`, `controls`, `environment`, `workspace`,
`execution`, and `cleanup` sections each carry their own state. Image evidence
distinguishes the configured reference, registry digest, local image ID, and
container-bound image ID. Cleanup evidence records bounded hashed container
identity, liveness verification, workspace cleanup, and overall completion.

Evidence is canonicalized with deterministic key ordering and strict enum,
shape, nesting, item-count, string-length, and serialized-size bounds. Known
credentials, configured sensitive values, control characters, raw Docker argv
and output, environment values, and host-private absolute paths are omitted or
redacted. Environment variable names may be recorded; their values are never
recorded. Portable path roles such as `${REPOSITORY_ROOT}` and `${RUN_ROOT}` are
used where a known artifact root is relevant.

This evidence proves only what AgentGuard configured and observed through its
trusted host-side Docker and filesystem checks. It is not a VM, syscall-level
isolation, container-escape, kernel-integrity, or honest-producer proof. Docker
Desktop retains its reduced claim level. SARIF and JUnit remain unchanged
because containment is run provenance rather than an individual finding or
testcase result.

For every container it successfully creates, `contained-run` binds cleanup to
the exact Docker container identity returned by Docker and verified through an
AgentGuard-owned label. Cleanup never selects targets using attacker-controlled
names alone. Bounded stop, kill, remove, and inspect operations are attempted
after success, agent failure, policy failure after workspace preparation,
timeout, cancellation, Docker launch failure after creation, output capture
failure, mutation/evidence processing failure, and unexpected exceptions after
creation. AgentGuard verifies absence or liveness with Docker inspection before
reporting success and before deleting the lifecycle-owned workspace. Cleanup
states distinguish removed, cleanly terminated, force-killed, already absent,
incomplete cleanup, and unavailable verification. A cleanup or liveness
verification failure fails the contained run even when the contained agent
exited successfully. When both execution and cleanup fail, the primary execution
failure remains the main failure and the cleanup failure is recorded separately
in the contained-run JSON artifact.

## Contained Workspace Lifecycle

AgentGuard includes an additive contained workspace lifecycle foundation for a
future contained runner. It prepares a lifecycle-owned host directory with a
`workspace/` tree for the untrusted agent and an external `evidence/` tree for
AgentGuard metadata. The original repository is never mounted as the writable
agent workspace.

Preparation copies the intended repository state into the isolated workspace
without inheriting `.git` control metadata. Before copying, AgentGuard records a
fixed baseline snapshot with deterministic path, type, mode, size, and SHA-256
metadata plus Git HEAD and porcelain status evidence when the source is a Git
worktree. That baseline is retained outside the agent-visible repository, so
later commits, branch changes, or HEAD movement cannot replace the pre-agent
comparison point.

Ownership metadata is explicit and deterministic: the prepared workspace records
the agent workspace mount, the external evidence mount, normalized agent-visible
writable paths, the AgentGuard evidence target, cleanup targets, reserved paths,
and lifecycle bounds. Writable paths must be unique and non-overlapping;
`.` is accepted only as the sole writable path. Reserved AgentGuard paths,
nested reserved paths, prefix collisions, escaping paths, duplicate ownership,
and ambiguous ancestor/descendant ownership are rejected.

Preparation and mutation capture both validate path and link boundaries. Safe
relative symlinks may be represented as symlinks only when they resolve inside
the prepared tree. Dangling links, absolute or escaping links, symlinks to Git
control metadata, special files, and hardlinks are rejected. Regular-file copy
uses a copy-time identity check so a source path replaced during preparation
fails closed instead of copying swapped content.

Mutation capture compares the current prepared workspace to the stored baseline
without consulting live Git metadata in the prepared workspace. It classifies
modified, added, deleted, and deterministic unique hash-based renames while
excluding AgentGuard evidence that lives outside the workspace. Agent-created
`.git` control metadata inside the prepared workspace is treated as reserved
path spoofing and causes capture to fail closed.

Preparation, scanning, hashing, and mutation capture are bounded by entry count,
per-file bytes, total bytes, and symlink-target bytes. Preparation is
transactional: partially prepared staging directories are rolled back on
failure. Cleanup removes only lifecycle-owned paths recorded for the prepared
workspace. Preparation, capture, cleanup, and recovery diagnostics are
controlled and sanitized so user-visible errors do not expose private absolute
host paths or credentials.

This lifecycle foundation is used by the public `contained-run` entrypoint. It
does not change Docker preflight semantics and does not change existing
benchmark, local-command, agent-command, suite, matrix, or CI behavior.

## Configuration Contract

The additive `contained_execution` config block is version-aware boundary
metadata for `contained-run`. It is validated by the loader and JSON Schema and
does not change current `run`, `ci`, `benchmark`, `suite`, `matrix`,
local-command, agent-command, or existing Docker test-runner behavior.

Accepted v1 shape:

```yaml
contained_execution:
  version: 1
  platform: linux-docker-engine
  network: none
  image_provenance: digest-required
  required_uid: 1000
  required_gid: 1000
  cpu_limit: 1.0
  memory_limit: 512m
  pids_limit: 256
  tmpfs_size: 256m
  require_evidence_outside_agent_repo: true
  allow_privileged: false
  allow_host_network: false
  allow_docker_socket_mount: false
  allow_device_exposure: false
  allow_host_namespace_sharing: false
  environment:
    - name: AGENT_API_TOKEN
      source: host
      required: true
      allow_sensitive: true
    - name: AGENT_MODE
      value: batch
```

`network: bridge` is accepted only when explicitly configured; omission defaults
to `none`. `platform: docker-desktop-experimental` is accepted only as a
reduced-claim value. Omitted optional fields take the conservative v1
defaults shown above. Attempts to opt into host networking, privileged
containers, Docker socket mounts, host devices, host namespaces, mutable
tag-only provenance, in-repository evidence, malformed limits, or unbounded
limits are rejected by configuration validation.

The optional `environment` list is the only way to pass user-configured
variables to the contained agent. Each entry has a `name`, an optional
`source` of `literal` or `host` (`literal` is the default), either a literal
`value` or an exact host lookup, optional `required`, optional `sensitive`, and
`allow_sensitive` for secret-like names or values intentionally marked
sensitive. Existing configs that omit `contained_execution.environment` remain
valid and run with only the fixed runtime defaults.

## Compatibility

Existing configs that omit `contained_execution` keep their current behavior.
Existing `sandbox.type: local` and `sandbox.type: docker` execution modes are
posture declarations for the current runner only; they are not upgraded into
contained-agent application-level boundaries by this contract.

The v1 JSON Schema remains additive and keeps package version `0.3.1`.

## Explicit Non-Goals And Non-Claims

Contained execution is not a formal isolation proof, malware analysis
environment, or substitute for least-privilege host credentials.

Container escape, malicious or vulnerable host kernels, malicious Docker daemon
behavior, compromised host administrators, side channels, supply-chain attacks
before image provenance validation, and denial-of-service against host resources
outside configured limits are out of scope.

AgentGuard does not claim that passing checks means an agent is safe,
trustworthy, or unable to leak secrets. It claims only that the configured
evidence and policy checks observed the run within the stated boundaries.
