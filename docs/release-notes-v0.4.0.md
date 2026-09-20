# AgentGuard v0.4.0 Release Notes

## Headline

AgentGuard v0.4.0 adds first-class opt-in contained execution for coding-agent
runs while preserving existing non-contained evaluation modes. The release
focuses on Docker capability preflight, least-privilege execution, isolated
workspace lifecycle, explicit environment policy, cleanup/liveness evidence,
and auditable containment records across AgentGuard artifacts.

## Contained Execution Capabilities

- `agentguard contained-run CONFIG -- AGENT_ARGV` runs one explicit argv through
  a contained-run boundary. The literal `--` is required, and child arguments
  are preserved as structured tokens rather than joined into a shell string.
- Docker preflight verifies bounded Docker CLI and daemon evidence before
  workspace preparation or agent launch. Linux Docker Engine is the
  authoritative platform for full contained-run claims.
- The Docker execution spec renderer emits deterministic argv from validated
  typed fields. It enforces non-root UID/GID, `no-new-privileges`, dropped
  capabilities, PID, CPU, and memory limits, read-only root filesystem, bounded
  tmpfs, default `network: none`, digest-pinned images, and no arbitrary raw
  Docker flags.
- The contained workspace lifecycle copies the evaluated repository into a
  lifecycle-owned workspace, keeps evidence outside the agent-visible
  repository, records a baseline before launch, captures mutations without
  trusting live Git metadata, and cleans up recorded lifecycle-owned paths.
- Environment forwarding is explicit. Contained runs receive fixed runtime
  defaults plus bounded configured allowlist entries only; ambient host
  environment variables, Docker client state, sockets, tokens, and credential
  stores are not forwarded.
- Cleanup and liveness verification are bound to immutable Docker container
  identity and AgentGuard-owned labels. Cleanup or liveness verification
  failures are recorded and fail the contained run.

## Security And Trust Boundaries

Docker-backed contained execution is application-level containment, not an
absolute hostile-code sandbox. AgentGuard does not claim VM isolation,
syscall-level confinement, container-escape prevention, host-kernel integrity,
or proof that all vulnerabilities are eliminated.

Linux Docker Engine is authoritative for full contained-run claims. Docker
Desktop is accepted only with reduced and experimental status because it adds a
desktop-managed VM and platform integration layer. The Docker daemon, host
kernel, host operating system, and host filesystem permissions remain trusted
computing base components.

Contained-run evidence proves only what AgentGuard configured and observed
through its host-side Docker and filesystem checks. It does not prove that an
agent is safe, trustworthy, or unable to leak secrets.

## Experimental Untrusted-Agent Preset

The experimental `untrusted-agent` preset generates a contained-run starter
configuration for `agentguard contained-run` only. It requires a digest-pinned
Docker image, defaults network to `none`, uses the explicit
`contained_execution.environment` allowlist, and does not forward ambient host
tokens or secrets. Ordinary `agentguard ci`, `local-command`, `agent-command`,
and other uncontained paths reject configs with `contained_execution` before
running tests or agents.

## Compatibility

Existing non-contained modes remain compatible when configs omit
`contained_execution`: `run`, `ci`, `benchmark`, `suite`, `matrix`,
`local-command`, `agent-command`, and the existing Docker test runner keep their
prior execution contracts. The distribution remains `agentguard-evals`; the
Python import and console command remain `agentguard`; supported Python
versions remain 3.9 through 3.12.

Upgrade or install from production PyPI:

```bash
python -m pip install --upgrade "agentguard-evals==0.4.0"
agentguard --version
```

For an isolated command installation:

```bash
pipx install "agentguard-evals==0.4.0"
agentguard --version
```

## GitHub Actions Adoption

The maintained contained-run GitHub Actions path is opt-in and copyable:
`examples/github-actions/agentguard-contained-run.yml`. It targets hosted Linux
Docker pull-request runners, uses read-only `contents` permission, pins
third-party Actions to immutable SHAs, checks out with credentials disabled,
verifies Docker before running `contained-run`, uses a digest-pinned image,
keeps network disabled by default, forwards no ambient GitHub token or secret
environment values, and uploads only the narrow contained-run evidence artifact.

## Validation Summary

Release preparation kept the protected publishing boundary unchanged:
release-only trigger, exact `v0.4.0` tag checks, protected `pypi` environment,
OIDC Trusted Publishing authority only in the publication job, immutable Action
SHA pins, build-once artifact reuse, and strict tag/ref/version validation.

Local release-preparation checks should include `git diff --check`, ordinary
package-context validation, focused release/publish validation tests, and
contained-run contract tests when dependencies are present. Local machines
without Docker can validate non-Docker release invariants but cannot provide
authoritative contained-run evidence; hosted Linux Docker evidence is required
for the full contained-run claim.
