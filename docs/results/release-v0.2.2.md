# AgentGuard v0.2.2 Release Verification

This versioned record documents the completed v0.2.2 production release. It is
not a live badge and does not replace older commit-scoped validation artifacts.

- Released: 2026-07-28
- Source commit: `dfc06fcbbd05fa924c5d7de861e28d6a9c379653`
- Git tag: `v0.2.2`
- [GitHub release](https://github.com/richinmrudul/agentguard/releases/tag/v0.2.2)
- [Production PyPI release](https://pypi.org/project/agentguard-evals/0.2.2/)
- [Trusted Publishing workflow run](https://github.com/richinmrudul/agentguard/actions/runs/30400888141)

## Published Identity

| Identity | Value |
| --- | --- |
| Product | AgentGuard |
| PyPI distribution | `agentguard-evals` |
| Python import package | `agentguard` |
| Console command | `agentguard` |
| Version | `0.2.2` |
| Supported Python | 3.9–3.12 |

The release used GitHub OIDC Trusted Publishing through the protected `pypi`
environment. No PyPI token or password was used. PyPI generated digital
attestations for the uploaded distributions.

## Release Validation

- Full test suite: 1,157 passed, 15 skipped.
- Release-artifact validation: passed.
- Isolated installed-wheel package smoke: passed.
- Adversarial and showcase metrics checks: passed.
- Ruff and diff checks: passed.
- Fresh public installation used `--no-cache-dir` and the production PyPI
  index.
- Installed metadata resolved as `agentguard-evals==0.2.2`.
- `import agentguard`, `agentguard --version`, and `agentguard --help` passed
  outside the source checkout.
- A network-free mock-agent evaluation passed with score 100/100.

The separately maintained
[validation summary](validation-summary.md) remains a dated, commit-scoped
coverage snapshot and was not rewritten for this documentation update.

## Artifact Verification

The public files downloaded from PyPI were byte-identical to the exact
validated distributions retained by the successful workflow:

| File | Workflow and public SHA-256 |
| --- | --- |
| `agentguard_evals-0.2.2-py3-none-any.whl` | `703e35376b94776318b8bbaf9fee91b78f97f9ae07d943b538a32a54d35997df` |
| `agentguard_evals-0.2.2.tar.gz` | `ce9608259cabcdf7248c09f39e992dba1b36d2dd4138438f3a354dff2cf401b4` |

Both archives reported metadata name `agentguard-evals`, version `0.2.2`, and
`Requires-Python: >=3.9`. The wheel retained the `agentguard` import package
and console entry point. Repository-only tests, docs, examples, workflows,
caches, and generated runtime state were absent.

## Historical And Scope Notes

AgentGuard v0.2.1 remains a valid GitHub-only release. PyPI rejected its
original distribution identity before upload, so no v0.2.1 package was
published. TestPyPI was intentionally unused because its relevant namespace is
unrelated to this project.

Local-agent execution is not inherently sandboxed and should not be treated as
a host security boundary. Docker-backed evaluations provide stronger isolation
when configured, but AgentGuard does not claim universal containment or formal
security certification.
