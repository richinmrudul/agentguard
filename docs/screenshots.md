# Visual Tour

These captures show real AgentGuard documentation and deterministic product
output. They use repository-provided synthetic fixtures, contain no external
agent or model activity, and make no claim about broader production adoption or
universal detection quality. See the
[source and sanitization record](assets/screenshots/README.md) for reproduction
details and limitations.

## Product overview

![AgentGuard hosted documentation homepage with product value proposition, navigation, v0.2.2 release, and PyPI installation command](assets/screenshots/agentguard-docs-home.png)

The public [AgentGuard documentation](https://richinmrudul.github.io/agentguard/)
puts the local-first evaluation model, current release, package identity, and
first installation commands on one screen. The visible navigation leads into
the architecture, benchmark, evidence, artifact, and integration guides.

## Evaluation dashboard

![AgentGuard static evaluation dashboard with eight deterministic records, result counts, scores, and benchmark categories](assets/screenshots/agentguard-dashboard.png)

The generated [static report site](static-site.md) summarizes six deterministic
showcase scenarios, their suite record, and one separate audit-mode incident
run. The single safe fixture scores 100 and passes; unsafe fixtures fail through
their configured checks. These counts describe this small demo corpus only.

## Guard incident detail

![Sanitized AgentGuard guard incident detail showing unsafe-command category, audit-only status, critical severity, timing, and bounded evidence summary](assets/screenshots/agentguard-incident-detail.png)

This real [online guard](online-guard.md) incident comes from the deterministic
`showcase_unsafe_command` fixture in audit mode. The page shows category, mode,
status, severity, timing, and a fixed evidence summary without rendering the
raw command payload, environment data, diff, or an absolute path.

## Evaluation evidence

![AgentGuard guard trends page showing deterministic run, incident, violation, failed-check, safe-pass, category, guard-type, and severity counts](assets/screenshots/agentguard-evaluation-evidence.png)

The static trend view aggregates the same generated records. It connects the
eight represented records to one sanitized command-guard incident, sixteen
failed checks, seven expected unsafe failures, and one safe pass. The
[showcase metrics](results/showcase-metrics.md) separately retain the committed
5/5 unsafe-detection and 1/1 safe-allowance evidence for the six-scenario
showcase.

## Interpretation boundary

These screenshots demonstrate reporting and evidence presentation, not a
perfect security boundary or a statistical effectiveness claim. Local agent
execution uses host-user permissions and is not inherently sandboxed. Docker
can provide configured containment for Docker-backed evaluations.
