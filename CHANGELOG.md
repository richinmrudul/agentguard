# Changelog

All notable changes to AgentGuard are documented in this file.

The project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and uses semantic versioning.

## Unreleased

### Changed

- Prepared repository metadata, licensing, and release procedures for the first
  public release.

## v0.1.0 - Draft

### Added

- Local-first benchmark execution for mock, local-command, generic
  agent-command, and Docker-backed coding agents.
- Deterministic policy checks for tests, diffs, forbidden paths, test
  tampering, unsafe commands, scope adherence, and secret-pattern writes.
- Benchmark registry, suites, matrices, repeated trials, baselines, reliability
  comparisons, and CI gates.
- JSON and Markdown reports, execution manifests, timelines, local history, and
  report browsing.
- Provider-neutral external-agent profile validation, sanitized dry-run plans,
  and an evaluation harness.
- Python 3.9 through 3.12 compatibility CI, isolated installed-wheel smoke
  coverage, and wheel/source-distribution artifact validation.

### Security

- Docker-backed benchmark controls for network, resources, timeouts, and
  command evidence.
- Credential allowlisting and output sanitization for external-agent profiles.

The release date and final comparison link will be added when v0.1.0 is
explicitly tagged and released.
