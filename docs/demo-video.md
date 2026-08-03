# AgentGuard Product Demo

This silent 80-second recording connects the released CLI, deterministic local
showcase, bounded metrics verification, sanitized static report, and production
installation path. It uses no external coding agent or model API.

Hosted availability begins with the GitHub Pages deployment that contains this
documentation change. The media and captions remain directly available from
the repository source in every revision that includes them.

<video controls preload="metadata" playsinline style="width: 100%; height: auto;"
  poster="../assets/screenshots/agentguard-dashboard.png">
  <source src="../assets/demo/agentguard-v0.2.2-demo.mp4" type="video/mp4">
  <track kind="captions" src="../assets/demo/agentguard-v0.2.2-demo.vtt"
    srclang="en" label="English" default>
  Your browser does not support embedded video. Open or download the
  <a href="../assets/demo/agentguard-v0.2.2-demo.mp4">AgentGuard v0.2.2 demo MP4</a>.
</video>

[Open or download the MP4](assets/demo/agentguard-v0.2.2-demo.mp4) ·
[Read the capture and sanitization record](assets/demo/README.md) ·
[Verify the SHA-256 manifest](assets/demo/SHA256SUMS)

## What the demo proves

The recording shows the production `agentguard-evals==0.2.2` command identity,
then runs the repository's six deterministic showcase fixtures. The real result
allows the one safe scenario and detects all five expected unsafe scenarios.
The matching metrics check verifies that curated result before the recording
moves through the static dashboard and one sanitized audit-only incident.

This is a compact product walkthrough, not a statistical effectiveness study.
It does not demonstrate an external model, production adoption, formal
certification, perfect detection, or inherent sandboxing of local execution.

## Transcript

**00:00–00:03 — CLI identity.** A neutral terminal displays
`agentguard --version`; the installed production command returns `0.2.2`.

**00:03–00:11 — CLI surface.** `agentguard --help` displays the real command
overview, including benchmark, suite, reports, guard, manifest, and trace tools.

**00:11–00:28 — Deterministic showcase.** The repository-provided
`scripts/showcase_demo.sh` command runs six synthetic fixtures without an
external agent or model API. Its concise output reports six scenarios, one safe
scenario allowed, and five unsafe scenarios detected across the configured
categories.

**00:28–00:43 — Evidence check.** The real
`scripts/showcase_metrics.py --check` output confirms 5/5 unsafe detections,
1/1 safe allowance, zero false positives, and zero false negatives for this
deliberately small corpus. The visible overhead value is a local showcase
measurement, not a benchmark-grade performance claim.

**00:43–00:53 — Dashboard.** The sanitized static report summarizes eight
represented records: the six showcase runs, their suite record, and a separate
audit-mode run used to demonstrate an incident.

**00:53–01:05 — Incident detail.** A slow pan shows the real sanitized
`showcase_unsafe_command` incident: failed evaluation, audit-only mode, one
critical command-policy violation, 98 ms to first violation, and the fixed
evidence summary “Command policy violation detected.” The raw command is not
rendered.

**01:05–01:10 — Return.** The recording returns to the static dashboard and its
bounded summary.

**01:10–01:20 — Install and learn.** The public documentation homepage closes
the recording with the product identity and
`python -m pip install agentguard-evals`, followed by `agentguard --version`
and `agentguard --help`.

## Continue

- [Installation and Quickstart](quickstart.md)
- [Reproducible Manual Demo](demo.md)
- [Showcase Evidence](showcase.md)
- [Static Report Sites](static-site.md)
- [Visual Tour](screenshots.md)
