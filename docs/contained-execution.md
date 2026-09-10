# Contained Execution Contract

AgentGuard's contained-execution contract defines the threat model for a future
workflow that launches an untrusted coding agent inside a constrained Docker
environment, preserves evidence outside that agent's mounted repository, and
fails before agent startup when required security properties cannot be verified.

This page is authoritative for containment claims. Existing execution modes
remain unchanged by this contract, including current benchmark, Docker,
local-command, and CI modes. The
`untrusted-agent` preset remains unavailable until AgentGuard has a complete
workflow that implements this contract end to end.

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
classification, the selected allowed network, requested resource-limit signals,
read-only-root and tmpfs API support, digest-pinned local image identity, a
controlled run as the required non-root UID/GID with a bounded writable tmpfs
path, and rejection of prohibited contained-execution options. Malformed,
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
repository is not mounted writable. Before launch, AgentGuard adjusts only the
lifecycle-owned prepared workspace copy so the configured non-root container
UID/GID can write task files even when the host checkout is owned by a different
developer or CI runner UID. The generated Docker argv comes only from the
validated contained-execution config and typed Docker execution spec. It uses
the configured non-root UID/GID, default `network: none` unless an explicit
validated `bridge` opt-in is present, read-only root filesystem, tmpfs `/tmp`,
capability drop, `no-new-privileges`, PID, memory, and CPU bounds. It does not
provide Docker socket mounts, host devices, host namespaces, privileged mode,
host networking, arbitrary host-path mounts, or arbitrary Docker flag strings.

The contained process receives no AgentGuard environment allowlist and no
arbitrary environment passthrough; broader environment allowlisting is future
work. The host subprocess that invokes Docker keeps only the minimal host
`PATH` needed to find the Docker CLI. A nonzero contained agent exit remains an
agent-command failure unless AgentGuard has specific Docker operational
evidence, such as Docker's launch failure status or a Docker subprocess error.

The command captures bounded stdout, stderr, exit status, timeout state,
workspace mutations, cleanup status, Docker preflight evidence, and a compact
contained-run JSON artifact with sanitized diagnostics. Existing post-execution
policy checks are evaluated against the captured workspace mutation summary
where feasible. This is not the broad report, trace, manifest, or incident
integration planned separately. `contained-run` does not provide a liveness
guarantee beyond bounded command timeout and best-effort owned container and
workspace cleanup reporting.

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

This lifecycle foundation is not a public contained runner, does not launch an
agent, does not execute repository code, does not change Docker preflight
semantics, and does not change existing benchmark, local-command,
agent-command, suite, matrix, or CI behavior.

## Configuration Contract

The additive `contained_execution` config block is version-aware planning
metadata. It is validated by the loader and JSON Schema so future examples can
declare the intended boundary, but it does not execute a contained runner or
change current `sandbox`, benchmark, local-command, Docker, or CI behavior.

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
```

`network: bridge` is accepted only when explicitly configured; omission defaults
to `none`. `platform: docker-desktop-experimental` is accepted only as a
reduced-claim planning value. Omitted optional fields take the secure v1
defaults shown above. Attempts to opt into host networking, privileged
containers, Docker socket mounts, host devices, host namespaces, mutable
tag-only provenance, in-repository evidence, malformed limits, or unbounded
limits are rejected by configuration validation.

## Compatibility

Existing configs that omit `contained_execution` keep their current behavior.
Existing `sandbox.type: local` and `sandbox.type: docker` execution modes are
posture declarations for the current runner only; they are not upgraded into
contained-agent application-level boundaries by this contract.

The v1 JSON Schema remains additive and keeps package version `0.3.1`.

## Explicit Non-Goals And Non-Claims

Contained execution is not a formal sandbox proof, VM isolation claim, malware
analysis environment, or substitute for least-privilege host credentials.

Container escape, malicious or vulnerable host kernels, malicious Docker daemon
behavior, compromised host administrators, side channels, supply-chain attacks
before image provenance validation, and denial-of-service against host resources
outside configured limits are out of scope.

AgentGuard does not claim that passing checks means an agent is safe,
trustworthy, or unable to leak secrets. It claims only that the configured
evidence and policy checks observed the run within the stated boundaries.
