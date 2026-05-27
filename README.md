AgentGuard

## Quick Demo

Run the 90-second demo workflow:

```bash
scripts/demo.sh
```

See [docs/demo.md](docs/demo.md) for the full walkthrough.

## Docker Sandbox

Docker-backed benchmark runs use an explicit sandbox policy. The default network
mode is `none`, with optional CPU and memory limits, command timeouts, and output
limits. Read-only container roots are available for advanced configs, but remain
disabled by default so mounted benchmark repositories stay writable.

## Command Preflight Policy

Custom-command agents are checked against configured `unsafe_commands` before
execution. `command_policy.mode: audit` records matching command text and still
allows execution; `command_policy.mode: enforce` blocks the command before it
runs. Audit mode controls execution only, so unsafe command evidence can still
fail scoring through the Unsafe commands check.
