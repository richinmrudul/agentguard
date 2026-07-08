# Changelog

All notable changes to AgentGuard are documented in this file.

The project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and uses semantic versioning.

## Unreleased

- No unreleased changes.

## v0.1.0 - Release Candidate

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
