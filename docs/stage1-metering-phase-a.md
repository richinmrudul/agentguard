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
disabled analytics, and disabled startup update checks. The existing image's
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

Retrieved 2026-10-14; frozen tool-spec source rechecked 2026-10-15. These are
the authoritative inputs used for Phase A:

- [Frozen Codex 0.159.2 provider configuration](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/model-provider-info/src/lib.rs) and [CLI override parsing](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/utils/cli/src/config_override.rs).
- [Frozen Codex Responses request construction](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/core/src/client.rs) and [request serialization](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/codex-api/src/common.rs).
- [Frozen Codex tool-spec serialization](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/tools/src/tool_spec.rs), including locally executed namespace wrappers.
- [OpenAI input-token counting](https://developers.openai.com/api/docs/guides/token-counting) and [endpoint reference](https://developers.openai.com/api/reference/resources/responses/subresources/input_tokens/methods/count).
- [Responses streaming terminal event and usage](https://developers.openai.com/api/reference/resources/responses/streaming-events) and [pricing source](https://developers.openai.com/api/docs/pricing).

These sources do not establish a final immutable Codex-compatible model,
pricing effective for that model, or live token-count billing. None is inferred.

## Phase B dependency order

1. Inspect the hosted frozen-CLI Docker proof and reconcile any exact wire
   differences. No skipped Docker result counts as proof.
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
