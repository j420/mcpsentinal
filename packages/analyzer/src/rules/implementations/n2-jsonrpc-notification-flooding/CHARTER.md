---
rule_id: N2
name: JSON-RPC Notification Flooding
interface_version: v2
severity: high
owasp: MCP07-insecure-config
mitre: AML.T0054
risk_domain: denial-of-service
threat_refs:
  - kind: spec
    id: JSONRPC-2.0-SEC-4.1
    url: https://www.jsonrpc.org/specification#notification
    summary: "JSON-RPC 2.0 Section 4.1 defines a Notification as a Request without an id. Because there is no response, the protocol provides no natural flow control — server or client can emit notifications at arbitrary rates and the peer has no back-pressure channel."
  - kind: spec
    id: MCP-2025-03-26-progress
    url: https://modelcontextprotocol.io/specification/2025-03-26/basic/utilities/progress
    summary: "MCP spec 2025-03-26 defines notifications/progress, notifications/resources/list_changed, notifications/tools/list_changed, and logging/message — all fire-and-forget. Servers emitting these in a loop without a bounded queue create denial-of-service amplification."
  - kind: paper
    id: Parity-JSONRPC-DoS
    url: https://github.com/paritytech/jsonrpc/issues/557
    summary: "Parity's JSON-RPC implementation documented a resilience model requiring bounded notification queues with drop-oldest backpressure. Absence of this pattern reproduces the 2017-2018 class of WebSocket server DoS incidents."
lethal_edge_cases:
  - id: setInterval-producer
    description: "Notification emission sits inside a setInterval callback. The interval timer is the loop the rule must recognise even though the closure itself contains no while/for keyword."
  - id: while-forever-producer
    description: "while(running) notify(msg) — the unbounded producer idiom. Textbook slowloris primitive for WebSocket/SSE."
  - id: notification-storm-via-batch-reply
    description: "For each incoming batch entry the handler emits a progress notification, so one inbound request produces N outbound notifications at wire speed. The loop is the outer batch handler, not a textual for/while."
  - id: ringbuffer-without-backpressure
    description: "Queue is present but unbounded (array.push with no length ceiling and no throttle). False negative for rules that look only for absence of a queue; the queue makes the memory pressure worse."
edge_case_strategies:
  - loop_emission_without_throttle
  - setinterval_emission_without_throttle
  - emit_call_in_enclosing_loop
evidence_contract:
  minimum_chain:
    source: true        # notification emitter reached from an unbounded loop
    sink: true          # per-iteration wire emit (notify/emit/send*)
    mitigation: true    # MUST report throttle / debounce / backpressure presence
    impact: true        # downstream saturation, client buffer exhaustion
  required_factors:
    - notification_emission_in_unbounded_loop
  location_kinds:
    - source
obsolescence:
  retire_when: "MCP transport SDKs ship with bounded notification queues by default (drop-oldest at ≤100) and the spec mandates server-enforced per-subscription rate limits."

mutations_survived: []
mutations_acknowledged_blind: []
---

# N2 — JSON-RPC Notification Flooding

## Threat narrative

JSON-RPC notifications are requests without an `id`, so the protocol never generates a response. This makes notifications asymmetric: one side can produce at arbitrary rate; the other side has no ACK to throttle on. MCP builds on this for `notifications/progress`, `list_changed`, and `logging/message` — all of which MCP clients render into UI state or append to a scrollback buffer.

A server that emits notifications inside a producer loop (while/for/setInterval) or in direct response to every inbound message, without applying throttle/debounce/rate-limit, hands the attacker a trivial amplification: send one message that puts the server in its producer loop, receive N messages back until the client buffer overflows or the network saturates.

The intelligence base is older than MCP: Parity's JSON-RPC resilience guidance (issue #557) explicitly requires bounded queues with drop-oldest backpressure, and the class of WebSocket server DoS incidents from 2017-2018 follows the same producer/consumer asymmetry. MCP inherits it on every transport that carries notifications (stdio, SSE, Streamable HTTP).

## Evidence contract

An auditor (EU AI Act Art. 15 robustness, ISO 27001 A.8.23 filtering) must see:

1. **Source**: a producer loop or interval where the AST shows a `notify()`, `emit()`, `push()`, `broadcast()`, `publish()`, `sendNotification()`, or `sendEvent()` call inside a loop-kind node or inside a `setInterval` callback.
2. **Sink**: the network-facing primitive — the same call, which from the peer's perspective is unsolicited wire traffic.
3. **Mitigation**: the enclosing function's source text must be inspected for `throttle`, `debounce`, `rateLimit`, `setTimeout`, `sleep`, `delay`, `break`, `return` — any of which indicates an intent to bound emission rate.
4. **Impact**: DoS amplification scoped to connected services; exploitability trivial.

## Lethal edge cases (tests cover)

- **setInterval-producer**: notification emission inside a `setInterval(() => notify(msg), ...)` callback. The loop is the interval, not a `while` keyword.
- **while-forever-producer**: `while(running) { notify(msg); }` — the classic primitive.
- **notification-storm-via-batch-reply**: for each incoming batch entry, a progress notification is emitted synchronously. The outer batch loop is the producer.
- **ringbuffer-without-backpressure**: a queue exists but is unbounded — absence-of-queue heuristics would miss this. The rule's throttle check catches it only when the enclosing function also lacks a size compare.

## Confidence ceiling

Cap at 0.85. Legitimate streaming servers (log tailers, progress reporters) intentionally emit high-rate notifications; the rule cannot distinguish "intentional stream" from "DoS primitive" without runtime data. 0.85 reflects this residual false-positive risk while keeping the finding above the compliance reporting threshold.
