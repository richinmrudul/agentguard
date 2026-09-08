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

The default network mode is `none`. A bridge network is future work and may only
be introduced as a validated opt-in with an explicit contract update. Until
that exists, bridge networking is outside the contained-execution contract.

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
  require_evidence_outside_agent_repo: true
  allow_privileged: false
  allow_host_network: false
  allow_docker_socket_mount: false
  allow_device_exposure: false
  allow_host_namespace_sharing: false
```

`platform: docker-desktop-experimental` is accepted only as a reduced-claim
planning value. Omitted optional fields take the secure v1 defaults shown
above. Attempts to opt into bridge networking, host networking, privileged
containers, Docker socket mounts, host devices, host namespaces, mutable
tag-only provenance, or in-repository evidence are rejected by configuration
validation.

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
