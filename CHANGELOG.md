# Changelog

All notable changes to AgentGuard are documented in this file.

The project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and uses semantic versioning.

## Unreleased

### Added

- Added a packaged, versioned Draft 2020-12 JSON Schema for `agentguard.yaml`,
  deterministic loader-contract and example validation in CI, and VS Code and
  YAML Language Server integration guidance.
- Added unreleased typed `minimal`, `recommended`, and `strict` CI policy
  presets, `agentguard init --preset`, and deterministic `agentguard presets
  list/show` inspection in text, YAML, and JSON.
- Added monotonic preset validation, production-path behavioral coverage, and
  documentation of the post-execution CI boundary. The misleading
  `untrusted-agent` name remains deferred until AgentGuard can launch agents
  through an enforced contained-execution workflow.
- Added unreleased `agentguard init [PATH]` project onboarding with dry-run,
  explicit conflict and force handling, conservative Python/pytest detection,
  argument-safe test-command storage, and optional least-privilege GitHub
  Actions generation.
- Added strict path and symlink containment, atomic known-target writes,
  idempotent reruns, `.gitignore` preservation, focused regression coverage,
  and hosted onboarding documentation for safe initialization.

## v0.2.2 - 2026-07-28

### Added

- Published AgentGuard's first production PyPI release as
  `agentguard-evals==0.2.2` through secretless GitHub OIDC Trusted Publishing,
  with digital attestations and a protected `pypi` environment.

### Changed

- Renamed only the PyPI distribution from `agentguard` to
  `agentguard-evals`; the AgentGuard product and repository, import package
  `agentguard`, and console command `agentguard` are unchanged.
- Updated the protected Trusted Publishing workflow for the v0.2.2
  release, including distribution-name, tag, version, filename, and artifact
  checks.
- Verified that the exact workflow wheel and source distribution were
  byte-identical to the public PyPI files and passed a clean no-cache
  installation and network-free smoke evaluation.

### Fixed

- Prepared a publishable distribution identity after PyPI rejected
  `agentguard` as too similar to another project. AgentGuard v0.2.1 remains a
  valid GitHub-only release and was not uploaded to PyPI.

### Compatibility

- No AgentGuard functionality was intentionally removed. Existing
  `import agentguard` usage and the `agentguard` terminal command remain
  compatible.

## v0.2.1 - 2026-07-27

### Added

- Prepared a production PyPI Trusted Publishing workflow for `v0.2.1` that
  builds and validates distributions once, preserves the exact artifacts, and
  gates OIDC publication behind the protected `pypi` GitHub environment.
  The workflow built and validated the release successfully, but publication
  failed before upload because the original distribution identity was rejected
  by PyPI.

### Changed

- Advanced the package and CLI release identity to `0.2.1` for post-v0.2.0
  bug fixes, reliability improvements, validation, and polish.
- Isolated local subprocess environments, tightened configuration validation,
  resolved suite-relative paths consistently, and restored matrix report
  browsing.
- Pinned the supported Ruff version so local and CI lint behavior agree.

### Fixed

- Hardened report generation, history CSV exports, artifact paths, agent event
  ingestion, subprocess output handling, Docker image validation, command
  redaction, static-site replacement, and staged rename inspection.
- Bounded recent-report parsing to avoid loading unbounded report histories.

## v0.2.0 - 2026-07-17

### Added

- `adversarial-core` benchmark pack foundation with deterministic local
  scenarios for prompt injection, dependency/script injection, secret
  exfiltration behavior, test tampering, scope drift, CI bypass, and hidden
  instruction following.
- Stable adversarial pack summary and metadata metrics artifacts under
  `docs/results/adversarial-pack-summary.*` and
  `docs/results/adversarial-metrics.*`.
- Opt-in built-in secret detector presets for bounded, redacted secret-content
  scanning across post-hoc and online guard flows.
- Filesystem watcher foundation with `auto`, `polling`, and `disabled` modes
  for online guard observability.
- Filesystem watcher hardening for rename/move representation, symlink
  create/change/delete events, rapid-change limitations, deterministic event
  ordering, deduplication, and event caps.
- Adversarial secret-detector benchmark coverage for fake GitHub-token-shaped,
  npm-token-shaped, and private-key-header content.

### Changed

- Release readiness artifacts summarize the post-v0.1.0 feature set recorded
  for the v0.2.0 release.
- Detection-quality and benchmark docs now distinguish the polished showcase
  from the broader adversarial-core evaluation pack.
- Online guard docs now document watcher modes, polling limitations, symlink
  behavior, and built-in detector redaction guarantees.

### Fixed

- Hardened filesystem watcher coverage for symlink and rapid-change cases
  without changing the current fallback semantics.
- Replaced a timing-sensitive parallel matrix integration assertion with a
  deterministic concurrency assertion.

### Safety/Security

- Built-in detector findings expose detector IDs and sanitized relative
  path/line evidence only; matched values and detector internals remain
  redacted from reports, traces, manifests, history, and static artifacts.
- Adversarial secret-detector scenarios use fake fixture values only and keep
  generated committed metrics free of fake secret values, raw diffs, absolute
  paths, environment values, and local runtime output.
- Filesystem watcher events store sanitized event metadata only and do not read
  or render file contents.

### Known Limitations

- No syscall-level interception is included.
- No privileged OS-native watcher integrations such as eBPF, fanotify, or
  FSEvents are included.
- No entropy detector is included.
- No user-provided regex detector is included.
- No hosted dashboard, cloud service, authentication, or team account model is
  included.
- The adversarial-core pack is an initial local-first coverage pack, not a
  broad benchmark corpus or leaderboard.
- PyPI publishing remains deferred.

## v0.1.0 - Released

### Added

- Local-first benchmark execution for mock, local-command, generic
  agent-command, and Docker-backed coding agents.
- Core benchmark and external-agent evaluation harnesses with profile
  validation, dry-run planning, suite/matrix execution, repeated trials,
  baselines, reliability comparisons, and CI gates.
- Deterministic policy checks for tests, diffs, forbidden paths, test
  tampering, unsafe commands, scope adherence, and secret-pattern writes.
- Runtime command and filesystem guard support, configurable guard ignore
  paths, live diff line enforcement, and structured guard incident artifacts.
- Post-hoc secret-content scanning and live configured secret-content guard
  enforcement for explicit detector literals.
- Benchmark registry, suites, matrices, repeated trials, baselines, reliability
  comparisons, and CI gates.
- JSON and Markdown reports, SARIF/JUnit exports, execution manifests,
  timelines, local history, report browsing, and static HTML report sites with
  incident pages and guard trend analytics.
- Guard incident history queries and CSV/JSON exports.
- Showcase demo pack, committed sanitized showcase summaries, and curated
  showcase metrics.
- Portable traces, replayability inspection, deterministic replay, and
  metamorphic trace diagnostics.
- Polished GitHub Actions CI gate, PR summary, showcase, and package
  validation examples.
- Python 3.9 through 3.12 compatibility CI, isolated installed-wheel smoke
  coverage, and wheel/source-distribution artifact validation.

### Changed

- Release documentation now separates local validation, CI artifact review,
  and post-merge tag/GitHub-release commands.
- Package metadata is aligned for v0.1.0 with MIT licensing, `README.md`
  inclusion, `agentguard` console script, and Python 3.9-3.12 classifiers.

### Fixed

- Hardened process termination cleanup for guarded agent execution.
- Hardened report, manifest, history, baseline, suite, and diagnostic writes
  with atomic replacement paths.
- Rejected duplicate YAML mapping keys across config, suite, profile, and
  registry inputs.

### Security/Safety

- Docker-backed benchmark controls for network, resources, timeouts, and
  command evidence.
- Credential allowlisting and output sanitization for external-agent profiles.
- Local command execution remains explicit and documented as not being a host
  security boundary.
- Release artifacts and committed result summaries avoid raw commands, raw
  diffs, secret values, configured fake secret literals, absolute workspace
  paths, and generated `.agentguard` runtime state.

### Known Limitations

- No syscall-level interception is included.
- No native filesystem watcher hardening is included.
- No built-in regex/entropy secret detector pack is included.
- No hosted dashboard, cloud service, authentication, or team account model is
  included.
- Curated showcase metrics are local demo metrics, not a scientific benchmark
  or production security-rate claim.
- PyPI publishing is deferred; v0.1.0 release artifacts are buildable and
  validated locally but are not uploaded by this repository.

The release date and final comparison link will be added only when v0.1.0 is
explicitly tagged and released after this release-candidate PR merges.
