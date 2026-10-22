# Stage 1 metering: Phase A

Issue #316 remains a prerequisite of #294. Phase A proves a **mock-only**
Responses metering contract. It does not freeze a live pilot, accept a real
credential, authorize a study, or create a publishable gateway image.

The successfully published Stage 1 gateway
`ghcr.io/richinmrudul/agentguard/stage1-gateway@sha256:39256ba5b6c25c741c49fd65b964cb254b642a416d67e045db20899660178ede`
is a destination-controlled byte-forwarding proxy. Its HTTPS `CONNECT` path
does not see individual Responses calls or terminal usage. It is **not eligible**
for #294 live execution or a spending-control claim. Its identity and registry
contents are unchanged by Phase A. The approved Codex agent digest remains
`ghcr.io/richinmrudul/agentguard/stage1-codex-agent@sha256:31402671e20d26972f0345c4bf3263d4f5309c0f450cfbaece19b2b799caa93a`.

## Frozen CLI boundary

Codex CLI 0.159.2 has a custom `model_provider` configuration with `base_url`,
`env_key`, `wire_api="responses"`, `requires_openai_auth=false`, and
`supports_websockets=false`. The reviewed `codex_metered_argv` uses global
`--ignore-user-config` and `-c` overrides, an internal
`http://stage1-metering-gateway:8080/v1` base URL, zero transport retries,
disabled analytics, disabled hosted web search, and disabled startup update
checks. The existing image's
entrypoint still requires `CODEX_API_KEY`; Phase A gives it only a synthetic,
mock-scoped value. The gateway rejects other paths and does not forward this
value to the mock provider. No ChatGPT account login or model discovery is
approved. The hosted Docker test is the required proof that the frozen binary
actually accepts these overrides; source inspection alone is insufficient.

Agent and gateway run on one Docker `--internal` network; only the gateway
joins a second `--internal` network containing the mock provider. The test
checks the agent has no direct provider route. No public network connection is
needed once pinned test images have been preloaded. Docker is an
application-level containment boundary, not a hostile-code sandbox guarantee.

## Metering contract

The only Phase A HTTP generation route is `POST /v1/responses`. The gateway
itself issues only `POST /v1/responses/input_tokens` and
`POST /v1/responses` to a fixed local mock. `GET /healthz` is local liveness
only. All other paths and methods, redirects, model/catalog discovery,
background mode, remote resources, uploads, hosted tools, and unknown fields
fail closed. A future live transport, if separately reviewed, must be restricted
to locally executed `function`/`custom` tool declarations, including the
bounded `namespace` wrapper used by frozen Codex 0.159.2. Nested namespace,
discovery, and hosted-tool declarations are rejected. It must connect
to `api.openai.com:443` and these exact two paths, with TLS verification and no
redirect following. Phase A contains no such transport or live secret resolver.
Remote-resource validation applies to request input content; local tool schema
property names are metadata, not remote resource invocations. Top-level
request fields and tool types remain separately allowlisted.

The gateway bounds JSON size/depth, tool schemas, input items, and output bytes;
requires the trial's exact model and `store=false`; injects or bounds
`max_output_tokens`; and obtains an authoritative input-token count before a
generation. It reserves worst-case **uncached** input plus maximum output cost
against both trial and study caps before generation. One generation may be in
flight per trial. No next generation is allowed until terminal Responses usage
reconciles with the pre-count. Both count requests and generation requests are
tracked. Missing, duplicated, out-of-order, truncated, unknown, or
contradictory usage closes the trial; a failed post-send reservation remains
consumed conservatively rather than being reported as measured cost.
Concurrent denial also closes an in-flight token-count operation before it can
send generation. If sanitized evidence cannot be written, the trial closes and
subsequent generation is denied.

The count call carries only the input-shaping fields documented by the count
endpoint (`model`, `instructions`, `input`, `tools`, `tool_choice`,
`parallel_tool_calls`, `reasoning`, and `text`). Generation-only controls such
as `stream`, `store`, and `max_output_tokens` are not sent to that endpoint.
The full generation request retains its enforced output cap, and any terminal
input-token disagreement with the pre-count fails closed.

The same rules handle buffered SSE `response.completed` and non-streaming
Responses JSON. Buffering prevents a second request until usage is validated.
It may increase latency and is bounded; this is explicitly a Phase A mock proof,
not a claim of live provider compatibility. The frozen CLI emits `stream=true`;
non-streaming coverage tests the protocol boundary independently.

`agentguard/schemas/stage1-pricing-policy-v1.schema.json` requires a dated,
exact-model USD policy with input, cached-input, and output rates per million
tokens. Its canonical digest is SHA-256 over sorted compact ASCII JSON plus a
newline. The policy uses `Decimal` and rounds each settled request **up** to
six USD decimal places. The Phase A model `stage1-mock-2026-10-14` and its
rates are synthetic test data, not reviewed provider pricing or a frozen pilot.
Live pricing would be reviewed and bound to an offline authorization; no trial
may fetch mutable pricing. Unknown usage categories and nonzero cache-write
tokens fail until separately priced and reviewed.

`agentguard/schemas/stage1-metering-evidence-v1.schema.json` bounds sanitized
evidence. Each event binds trial ID, plan digest, authorization digest, exact
model, pricing digest, monotonic request sequence, count request count, token
usage, and calculated token cost. This is not a measured provider bill. It
contains no raw prompt, output, request body,
query, authorization header, cookie, real or synthetic token, or host path.
Failed mock requests retain only a bounded static validation reason for
diagnosis. A fixed-format denial code is also sent to local container stderr
if evidence cannot be read. The Docker regression reads at most 64 KiB of
sanitized evidence through the same non-root container user, retains it outside
the container before cleanup, and filters only denial codes and liveness on
failure, never request bodies or unrestricted logs.
The gateway creates current-run evidence only and refuses a stale evidence
file. In-memory study accounting is suitable for mock proof only; Phase B must
provide crash-safe, cross-trial reservations before a live authorization can
be created.

## Source record

Retrieved 2026-10-14; frozen tool-spec, web-search configuration, and SSE
parser source rechecked 2026-10-15. These are
the authoritative inputs used for Phase A:

- [Frozen Codex 0.159.2 provider configuration](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/model-provider-info/src/lib.rs) and [CLI override parsing](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/utils/cli/src/config_override.rs).
- [Frozen Codex Responses request construction](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/core/src/client.rs) and [request serialization](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/codex-api/src/common.rs).
- [Frozen Codex tool-spec serialization](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/tools/src/tool_spec.rs), including locally executed namespace wrappers.
- [Frozen Codex web-search mode](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/protocol/src/config_types.rs) and [configuration resolution](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/core/src/config/mod.rs), which permit `web_search="disabled"`.
- [Frozen Codex Responses SSE parser](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/codex-api/src/sse/responses.rs), which handles output-item and text-delta events.
- [OpenAI input-token counting](https://developers.openai.com/api/docs/guides/token-counting) and [endpoint reference](https://developers.openai.com/api/reference/resources/responses/subresources/input_tokens/methods/count).
- [Responses streaming terminal event and usage](https://developers.openai.com/api/reference/resources/responses/streaming-events) and [pricing source](https://developers.openai.com/api/docs/pricing).

These sources do not establish a final immutable Codex-compatible model,
pricing effective for that model, or live token-count billing. None is inferred.

## Phase B dependency order

1. Preserve the hosted frozen-CLI Docker proof and extend it for every live
   transport change. No skipped Docker result counts as proof.
2. Add and review a production gateway transport and live-only credential
   resolver. The real `CODEX_API_KEY` must exist only inside that gateway;
   the agent receives only a synthetic trial-scoped value. Add crash-safe
   study-wide reservations and verify token-count billing semantics.
3. Prove an exact dated model snapshot, complete path/destination set, and
   current reviewed pricing. Freeze limits and redaction rules; reject any
   unsupported provider/model combination.
4. Build and scan a **replacement gateway image**. A replacement agent image
   is required only if the frozen CLI cannot accept the reviewed static
   provider configuration without changing its current image contract.
5. Separately authorize image publication, attest and pull back immutable
   subjects, repeat mock and security checks, and freeze digest-bound study
   profiles. Rejected publication digests remain ineligible.
6. Only after another read-only readiness review may #294 seek a separate
   offline authorization and, later, explicit live-trial approval.

No real credential, OpenAI request, billable call, or live authorization is
involved in Phase A. The old `study-egress` route remains non-metering.

## Phase B1 source-only boundary

Phase B1 adds a separate, still-disabled live transport contract. The only
reviewed upstream destination is `api.openai.com:443`, using system-CA TLS and
the exact hostname as SNI. Every DNS answer is checked for globally routable
addresses before a direct connection. Proxy and alternate-CA environment
controls, redirects, a second host, and every path other than
`POST /v1/responses/input_tokens` and `POST /v1/responses` are denied.
The agent-side network remains internal-only; this transport is never placed
in the agent container. The repository-controlled test variant connects only
to a local TLS mock using a test-only CA and fake credential. Neither variant
is enabled by `study-auth live-run` for Stage 1.

The reviewed model is `gpt-5.2-2025-12-11`. The frozen price artifact is
`agentguard/evaluation/stage1_pricing_v2.json`, retrieved 2026-10-22, with
canonical digest
`sha256:11da095d2856b07a2ce0a6da30e8d3229b9d4a2138122549d129580f0378eb35`.
It records standard USD prices per million tokens: uncached input 1.75,
cached input 0.175, and output 14.00. Reported output includes reasoning and
other non-visible generated tokens. Each request is rounded **up** to six
decimal places using exact decimal arithmetic. The source does not state a
separate price-effective date, so that field is null, not inferred from the
snapshot date. A pricing change requires a new reviewed policy and digest.

The gateway normalizes a generation from the frozen CLI to an exact dated
model, the three ordered declaration digests reviewed in PR #318, stream mode,
`reasoning.effort=none`, `store=false`, bounded output, and in-memory cache
retention. Unknown tools or request fields, hosted resources, non-text input,
reasoning summary, verbosity, extended cache retention, and nonstandard tiers
fail closed. The input-token count is derived from the normalized generation's
input-shaping fields. A terminal response must reconcile the count, model,
service tier, total tokens, cached input, and output including reasoning.
Cache-write usage is rejected because it is not priced in this policy.

The future real `CODEX_API_KEY` can be read only by the gateway's one-shot
resolver after image subjects, authorization, plan, trial, profile, model,
destination, pricing, redaction, and remaining ledger budget agree. Its
approved replacement-subject set is intentionally empty in B1. The agent
would receive only a random trial-scoped synthetic token. Python cannot
guarantee erasure of immutable strings from memory, so B2 must keep the
gateway process short-lived and never expose its environment or memory to
the agent; no claim of cryptographic memory erasure is made.

The host-side `agentguard.stage1-study-ledger` v1 snapshot and hash-chained
journal are private (0700 directory, 0600 files), locked across processes,
written with fsync and atomic snapshot replacement, and never agent-mounted.
Before generation, a count request and worst-case uncached-input plus maximum
output cost are reserved durably against trial and study limits. Terminal
authoritative usage settles only the unused delta. An outstanding reservation,
crash, malformed usage, truncated journal, snapshot/journal disagreement, or
replay blocks further provider work; it does not automatically refund a
possible charge. The local directory is trusted host storage. Malicious
rollback of the *entire* directory by a privileged operator cannot be
detected without an external monotonic anchor, which remains a Phase B2
deployment requirement.

Official sources rechecked 2026-10-22:

- [GPT-5.2 snapshot, Responses support, and model rates](https://developers.openai.com/api/docs/models/gpt-5.2).
- [Responses input-token count endpoint](https://developers.openai.com/api/reference/resources/responses/subresources/input_tokens/methods/count).
- [Responses create fields and terminal usage](https://developers.openai.com/api/reference/resources/responses/methods/create).
- [Output-token and non-visible-token accounting](https://developers.openai.com/api/docs/guides/token-counting).
- [Prompt-cache retention and separately priced writes](https://developers.openai.com/api/docs/guides/prompt-caching).

Phase B2 still requires replacement patched-agent and metering-gateway images,
deterministic identities, SBOM and vulnerability review, image-level mock
integration, build-once protected publication, pull-by-digest verification,
subject-digest attestations, and a final digest-bound profile and plan freeze.
The published byte-forwarding gateway remains ineligible for #294. No real
credential, OpenAI request, paid call, image publication, live authorization,
or live trial is part of B1.
