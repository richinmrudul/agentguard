# AgentGuard Portfolio Summary

AgentGuard is a local-first safety and evaluation platform for AI coding
agents. It runs reproducible benchmark suites, watches command and filesystem
behavior, and turns policy evidence into reports, traces, manifests, CI gates,
and static dashboards.

## Resume Bullets

- Built AgentGuard, a local-first safety/evaluation platform for AI coding
  agents, detecting unsafe commands, filesystem boundary violations, test
  tampering, secret-content introduction, and suspicious diffs across
  reproducible benchmark runs.
- Designed runtime and post-hoc guardrails with structured incidents, traces,
  replay, manifests, CI exports, and static dashboards for auditing agent
  behavior.
- Added adversarial benchmark packs and metrics covering hidden instruction
  following, CI bypass attempts, secret introduction, dependency/script
  injection, and scope drift.
- Released v0.2.0 as a public GitHub release with package smoke validation,
  GitHub Actions examples, static reports, and a release-operator validation
  suite reporting 987 passed tests, 15 skipped tests, and 1 warning.

## STAR Story

**Situation:** AI coding agents can produce working patches while also changing
tests, leaking secret-like content, weakening CI, or touching files outside the
requested scope.

**Task:** Build a local-first harness that evaluates agent behavior with
inspectable evidence rather than model self-reports.

**Action:** Implemented benchmark and suite execution, online command and
filesystem guards, post-hoc policy checks, secret-content detectors, traces,
replay, manifests, CI examples, static report sites, and adversarial metrics.

**Result:** AgentGuard v0.2.0 is published on GitHub with curated showcase
metrics detecting 5/5 unsafe scenarios, allowing 1/1 safe scenario, and
recording 0 false positives and 0 false negatives, plus a 10-scenario
`adversarial-core` pack and a full release validation run of 987 passed tests,
15 skipped tests, and 1 warning.

## Technologies And Systems

- Python 3.9-3.12, Typer CLI, PyYAML, pytest, Ruff
- Git diff and repository fixture orchestration
- Runtime command policy and process termination paths
- Portable polling filesystem watcher and online guard incidents
- Secret-content scanning with configured literals and built-in detector presets
- JSON/Markdown reports, static HTML report site, history, traces, replay, and
  manifests
- GitHub Actions CI gate examples and summary artifacts
- Deterministic benchmark packs, adversarial metrics, and release validation

## Metrics To Cite

- `v0.2.0` is a published GitHub release; no PyPI publish has been performed.
- Release-operator validation: 987 passed tests, 15 skipped tests, 1 warning.
- Showcase metrics: 5/5 unsafe scenarios detected, 1/1 safe scenario allowed,
  0 false positives, 0 false negatives.
- Adversarial coverage: 10 deterministic `adversarial-core` scenarios across
  CI bypass, dependency/script injection, hidden instructions, prompt
  injection, scope drift, secret-content introduction, secret-path
  exfiltration behavior, and test tampering.
- Evidence outputs: reports, guard incidents, traces, replay, manifests,
  history, static site pages, trend analytics, and CI exports.
