# Stage 1 metering protocol v1

Status: experimental candidate, local mock only. This contract does not enable
live startup, a real credential, a public provider route, or image publication.
The exact-image crash and filesystem fault proof belongs to #327; final runtime
approval belongs to #328.

## Inbound HTTP

The gateway accepts HTTP/1.1 origin-form `POST /v1/responses` only. It requires
one `Content-Type: application/json`, one canonical decimal
`Content-Length` in `1..=2,097,152`, and the exact internal synthetic bearer
token. The hostname is `stage1-metering-gateway:8080`. The frozen Codex
headers accepted by the Rust parser are enumerated in `http.rs`; no header is
forwarded upstream. Duplicate headers, transfer encoding, cookies, proxy
authorization, unreviewed headers, controls, malformed framing, an extra body
byte in the parsed message, and unsupported methods or targets are rejected.
The gateway sends one response and closes the connection; it never dispatches
a second request from the same connection.

Generation JSON is bounded by the same byte limit, maximum nesting 24,
maximum 128 elements per array/object, maximum 64 KiB per string and tool
declaration set. Duplicate JSON keys and floating-point numbers are rejected.
The request must name `gpt-5.2-2025-12-11` and the exact three reviewed tool
declarations. The gateway derives input-count JSON from the normalized
generation request, obtains authoritative input count, then durably reserves
worst-case generation cost before sending generation. Only the internal gateway
may call upstream `POST /v1/responses/input_tokens` and
`POST /v1/responses`.

## Upstream SSE

The local mock path requires `text/event-stream`, bounded HTTP/1.1 framing
and a stream no larger than 2 MiB. Every frame is `data: <JSON>\n\n`, at
most 64 KiB, with at most 256 frames. The accepted event order is:

1. exactly one `response.created` with an in-progress response ID and exact model;
2. zero or more ordered `response.output_item.added`, optional
   `response.output_text.delta`, then matching `response.output_item.done`
   pairs, one active output item at a time;
3. exactly one `response.completed` with the same response ID, exact model,
   completed status, standard service tier, output exactly matching the done
   items, and complete authoritative usage;
4. optionally one final `data: [DONE]` marker.

Sequence numbers start at zero or one and must then increase by exactly one.
Item IDs and output indices must
match. Unsupported fields or event types, completed-only streams, terminal
failure/incompletion, duplicate or post-terminal events, malformed frames, and
missing or inconsistent usage fail closed. The terminal usage must reconcile
input, cached input, output, reasoning, and total tokens with the independently
counted input before the ledger can settle. A stream error after reservation
leaves the full worst-case charge and closes the trial; no automatic replay is
permitted. Errors are persisted only as bounded classes, never raw frames,
prompts, output, headers, credentials, or provider bodies.

The deliberate completed-only rejection is narrower than the complete
[OpenAI Responses streaming event reference](https://developers.openai.com/api/reference/resources/responses/streaming-events):
the reference documents `response.created` and `response.completed` as
separate lifecycle events, but does not establish completed-only as sufficient
for this metered path. Ambiguity is rejected rather than treated as approval.

## Case Matrix

| Case | Threat | Decision / accounting / replay | Test level and name |
| --- | --- | --- | --- |
| H01 | Unsupported method, target or version | Reject before generation; no reservation; no replay of malformed request | Rust `http_framing_and_routing_reject_ambiguity` |
| H02 | Duplicate Host or Content-Length | Reject before generation; no reservation | Rust `http_framing_and_routing_reject_ambiguity` |
| H03 | Content-Length with Transfer-Encoding | Reject before generation; no reservation | Rust `http_framing_and_routing_reject_ambiguity` |
| H04 | Trailing/pipelined request bytes in parsed message | Reject before generation; no reservation | Rust `http_framing_and_routing_reject_ambiguity` |
| H05 | Premature EOF, zero/overflowing body length | Reject before generation; no reservation | Rust `http_framing_and_routing_reject_ambiguity` |
| H06 | Redirect, compression, ambiguous chunking/trailers | Reject upstream; retain full reservation if generation sent; block replay | Rust `http_framing_and_routing_reject_ambiguity` |
| H07 | Duplicate framing header against exact scratch gateway | Reject; close trial; no extra provider request | Hosted Docker `test_compiled_gateway_with_patched_codex_tls_and_ledger` |
| S01 | Valid mock lifecycle | Settle only after terminal usage; sequential next request permitted | Rust `sse_exact_lifecycle_and_completed_only_rejection`, hosted Docker `test_compiled_gateway_with_patched_codex_tls_and_ledger` |
| S02 | Completed-only, empty, heartbeat-only stream | Reject; retain reservation; block replay | Rust `sse_exact_lifecycle_and_completed_only_rejection` |
| S03 | Response or output-item identity mismatch | Reject; retain reservation; block replay | Rust `sse_identity_order_replay_and_terminal_usage_fail_closed` |
| S04 | Reordered, duplicated or replayed event | Reject; retain reservation; block replay | Rust `sse_identity_order_replay_and_terminal_usage_fail_closed` |
| S05 | Missing, malformed or contradictory terminal usage | Reject; retain reservation; block replay | Rust `sse_identity_order_replay_and_terminal_usage_fail_closed` |
| S06 | Truncated frame, duplicate JSON key, unreviewed event field | Reject; retain reservation; block replay | Rust `sse_identity_order_replay_and_terminal_usage_fail_closed` |
| S07 | Missing event, failed/incomplete terminal, unreviewed provider tool | Reject; retain reservation; block replay | Rust `sse_identity_order_replay_and_terminal_usage_fail_closed` |
| S08 | Invalid UTF-8, unsupported SSE field, oversized frame | Reject; retain reservation; block replay | Rust `sse_identity_order_replay_and_terminal_usage_fail_closed` |

The table records implemented cases, not an assertion that the whole
production transport and fault matrix is complete. The remaining exact-image
crash, restart, fsync, rename, and cleanup boundaries are tracked by #327.
