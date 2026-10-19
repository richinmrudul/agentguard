# Stage 1 dated-model compatibility prerequisite

Issue #316 remains open. This is a mock-only source/build candidate for
`gpt-5.2-2025-12-11`, not a pilot freeze, live credential path, or approved
replacement image. The published Codex agent digest
`sha256:31402671e20d26972f0345c4bf3263d4f5309c0f450cfbaece19b2b799caa93a`
contains the unmodified 0.159.2 binary and has no record for this snapshot.
It remains valid for its reviewed purpose but is not eligible for this dated-model
pilot without separate replacement-image review and publication.

## Frozen source and selection

The upstream source is `openai/codex` annotated tag `rust-v0.159.2`
(`8b9fa496bbf2c47aebd62e85a080b9a522a455b5`), commit
`ff6aec96948b70d94983af2641a6b67c94faeff5`, tree
`406dfdd5c68f303a3a8d04f32b3965b3b0ca0361`. Its Rust toolchain is
`1.95.0`; `codex-rs/Cargo.lock` is SHA-256
`4fab6fe99180e2b8f305bd4b33c1b4bd825e3fa4cdef1045be750843bd3d431e`.
Cargo 1.95 normalizes the frozen lockfile's local workspace package versions
from `0.0.0` to the manifests' `0.159.2` before a locked build. The build
script accepts only paired changes of those exact version lines, rejects any
dependency/source/checksum change, then uses `--locked` and records the
normalized lockfile hash. This is build-input normalization, not an upstream
source or dependency update.
The source is Apache-2.0; the frozen `LICENSE` and `NOTICE` SHA-256 values are
`d17f227e4df5da1600391338865ce0f3055211760a36688f816941d58232d8dc`
and `9d71575ecfd9a843fc1677b0efb08053c6ba9fd686a0de1a6f5382fd3c220915`.
The source patch at
`runtime-images/codex-agent/model-gpt-5.2-2025-12-11.patch` has SHA-256
`00c4a5f5e690b1b09f440cfbaa3e98ed7799066009ad500ad399461c20b55a95`.
The source-built candidate reports upstream version 0.159.2; the local
mock-only derivative image is labeled
`0.159.2+agentguard-model-gpt-5.2-2025-12-11` to distinguish it from the
published upstream-package image. No stable replacement binary or image digest
is claimed before a reproducible hosted build. The hosted compatibility check
uses a locked Linux musl debug binary to prove selection and wire behavior;
the production replacement in Phase B2 still requires a separately reviewed
optimized binary and build identity.

The frozen bundled catalog contains no `gpt-5.2` family or dated snapshot.
The [model manager](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/models-manager/src/manager.rs)
uses longest-prefix matching and otherwise calls the
[unknown-model fallback](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/models-manager/src/model_info.rs).
The unmodified binary consequently gives this exact snapshot fallback
metadata: no supported reasoning-level list, 272,000 context tokens, 95%
effective context, a 10,000-byte tool-output truncation rule, generic local
instructions, reasoning summary `auto`, no verbosity, and a warning instead
of refusal. These can alter compaction, instructions, request controls, and
study accounting. A new tag, provider base URL, or context override does not
fix the missing record.

Option A fails because supported config overrides change context, compaction,
tool truncation, and prompt text but not the full `ModelInfo`. Option B fails
because `model_catalog_json` loads a path without verifying its digest, and a
missing slug still falls back. The reviewed candidate is option C: add an exact
bundled record, disallow prefix/namespaced matching for it, and terminate if
that record is absent. The static record is compiled into the source-built
binary, not loaded from a mutable runtime path. The source test deliberately
removes the record and requires fail-closed termination.
Its short `base_instructions` string is an explicit AgentGuard-local task
instruction, not an inferred model capability or a claim that the unmodified
Codex prompt is preserved. The frozen catalog parser requires a nonempty
instruction template before any model can be selected.

## Capability mapping

Official [GPT-5.2 model documentation](https://developers.openai.com/api/docs/models/gpt-5.2)
retrieved 2026-10-15 lists the dated snapshot, Responses and streaming,
function calling, text input/output, 400,000 context, 128,000 maximum output,
and reasoning efforts `none`, `low`, `medium`, `high`, `xhigh`. The
[official model guide](https://developers.openai.com/api/docs/guides/latest-model?model=gpt-5.2)
retrieved 2026-10-15 describes custom function tools and tool-call parallelism.
The [Responses API](https://developers.openai.com/api/reference/resources/responses/methods/create)
defines the request controls; Codex 0.159.2's
[client](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/core/src/client.rs)
and [SSE parser](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/codex-api/src/sse/responses.rs)
determine how they are emitted and consumed.

| Metadata | Candidate value and provenance |
| --- | --- |
| Model ID | Exact `gpt-5.2-2025-12-11`; official dated snapshot. No alias or prefix match. |
| Context and compaction | 128,000 context/max, 100,000 auto-compact, 80% usable input; AgentGuard restrictions below the documented 400,000 limit. |
| Reasoning | `none` default; only the five officially documented efforts listed. The later pilot must freeze one exact effort. |
| Summary and verbosity | Summary parameter disabled, default summary `none`, verbosity disabled; conservative omissions rather than inferred support. |
| Input modalities | Text only; an AgentGuard restriction. No image/audio path is approved. |
| Tools | Unified local shell and freeform patch declarations, grounded in documented function/custom tool support and frozen Codex tool serialization. Hosted mock checks actual declarations; no hosted/provider tools are enabled. |
| Parallel calls | Frozen Codex sends `parallel_tool_calls=true` with ordinary Responses; the model guide documents tool-call parallelism. The metering gateway still allows only one in-flight generation per trial. |
| Streaming | Ordinary Responses SSE, not Responses Lite or WebSockets; official streaming support and frozen SSE parser. |
| Prompt | Short static AgentGuard-local `base_instructions`; this is a client instruction, not a claim about model capability. |
| Truncation | 10,000 bytes of tool output; conservative local limit. |
| Advanced features | No model search, image-original, experimental context/tools, reasoning-effort updates, hosted web search, multi-agent mode, extra service tier, or node REPL. |
| Pricing | Official model page quotes USD 1.75 input, 0.175 cached input, and 14 output per million tokens. This prerequisite does not freeze a pricing policy or authorize spending. |

The expected generation is `POST /v1/responses` with the exact dated model,
`stream=true`, `store=false`, `tool_choice=auto`, bounded local tool
declarations, `parallel_tool_calls=true`, `reasoning.effort=none`, no summary
or verbosity, and a gateway-bounded `max_output_tokens`. The gateway's sole
upstream count operation is `POST /v1/responses/input_tokens`. The hosted test
uses synthetic prices, an internal-only Docker network, and a repository
mock that records only bounded field names and enum projections. It rejects
unexpected model names and does not forward or contact a provider.
The metered argv explicitly sets `agents.enabled=false` and disables the frozen CLI's multi-agent,
apps/plugins, view-image, sleep, and interactive-input tools. The mock accepts
only the remaining local `exec_command`, `write_stdin`, and `apply_patch`
declarations; an additional tool fails the compatibility proof.

## Replacement dependency

The mock-only candidate is layered locally over the approved agent image for
compatibility testing; it is never pushed. Before #294 can use this model:

1. Build the minimal patched Codex binary from the pinned source, patch, lock,
   and toolchain; retain binary digest and explicit AgentGuard patch identity.
2. Create and review a replacement agent Dockerfile. Keep non-root execution,
   read-only root, no package installation at runtime, and the internal-only
   provider configuration. Verify local shell/patch tooling needed by both
   candidate fixtures.
3. Include binary, static catalog, and config in deterministic canonical
   identity. Generate SBOM, scan vulnerabilities, review licenses and notices,
   and retain source/patch provenance.
4. Run mock-only Codex-to-metering-gateway integration with tool calls and
   bypass denial; no public DNS or provider requests.
5. Add a build-once protected publication workflow, then separately authorize
   GHCR publication. Resolve and attest the new immutable digest.
6. Pull by digest and repeat metadata, request-shape, tool, metering, and
   containment checks. Reject unexpected content.
7. Freeze a new agent profile, plan, pricing policy, and offline authorization
   inputs only after gateway transport/ledger work and the new image digest are
   independently reviewed.

The existing agent image is not marked generally unsafe. No live credential,
public inference request, paid call, authorization, or pilot is part of this
prerequisite. Issue #294 remains blocked.
