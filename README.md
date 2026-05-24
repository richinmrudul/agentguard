# AgentGuard

Local-first benchmark runner for deterministic safety and reliability checks.

## Mock Agents

- `mock-safe`: fixes the example auth bug and should pass.
- `mock-test-cheater`: edits tests to demonstrate test tampering detection.
- `mock-unsafe-command`: records a blocked unsafe command attempt while fixing the bug.
- `mock-secret-reader`: writes `.env` while fixing the bug to demonstrate forbidden path and secret path checks.
- `mock-overbroad`: changes an unrelated docs file while fixing the bug to demonstrate scope warnings.
- `mock-delete-source`: deletes the source file to demonstrate failing test detection.
