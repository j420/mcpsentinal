---
rule_id: N1
name: JSON-RPC Batch Request Abuse
interface_version: v2
severity: high
owasp: MCP07-insecure-config
mitre: AML.T0054
risk_domain: protocol-transport
threat_refs:
  - kind: spec
    id: JSONRPC-2.0-SEC-6
    url: https://www.jsonrpc.org/specification#batch
    summary: "JSON-RPC 2.0 Section 6 permits an array of request objects as a single batch — but places NO limit on batch size. Servers MUST enforce one explicitly or accept unbounded amplification."
  - kind: spec
    id: MCP-2025-03-26-batching
    url: https://modelcontextprotocol.io/specification/2025-03-26/basic/transports
    summary: "MCP inherits JSON-RPC 2.0 batching for Streamable HTTP transport. The MCP spec does not mandate batch size limits; servers that parse arrays without a ceiling inherit the JSON-RPC DoS amplification class."
  - kind: incident
    id: CometBFT-2867
    url: https://github.com/cometbft/cometbft/issues/2867
    summary: "CometBFT JSON-RPC server accepted unbounded batch requests, permitting attackers to exhaust CPU and memory by sending a single TCP connection containing thousands of method calls. Fix added a configurable max_batch_size (default 20)."
  - kind: incident
    id: LSP-PR-1651
    url: https://github.com/microsoft/language-server-protocol/pull/1651
    summary: "Language Server Protocol debated disallowing JSON-RPC batch entirely after repeated amplification incidents in client/server implementations."
lethal_edge_cases:
  - id: batch-within-batch
    description: "Nested Array.isArray checks where an inner array of requests lives inside a 'payload' field, bypassing a naive outer .length check on the wrapper object."
  - id: map-without-guard
    description: "request.batch.map(handle) iterates a batch-named array without any length check — the idiomatic JS shape that produces no finding under pure string matching but is the actual DoS primitive."
  - id: notification-storm-via-batch
    description: "Batch composed entirely of notifications (no id field) — attacker packs N notifications in a single round-trip and the server processes them without ever reaching a response-mismatch check."
  - id: recursive-dispatch
    description: "Handler dispatches each batch entry by method name and the per-method handler itself recursively processes sub-arrays, multiplying the batch amplification."
edge_case_strategies:
  - array_isarray_with_unbounded_iteration
  - batch_named_variable_direct_iteration
  - batch_handler_without_length_guard
evidence_contract:
  minimum_chain:
    - source
    - sink
    - mitigation
    - impact
  required_factors:
    - unbounded_batch_iteration
  location_kinds:
    - source_code_line
obsolescence:
  retire_when: "MCP spec mandates a server-enforced max batch size with a protocol-level rejection code, AND >90% of tracked MCP SDKs set a bounded default."
---

# N1 — JSON-RPC Batch Request Abuse

## Threat narrative

JSON-RPC 2.0 permits a client to submit a batch of requests as a JSON array in a single round-trip. The specification (Section 6) describes batching as an optional optimization but imposes no upper bound on the array length. MCP inherits this semantic wholesale for the Streamable HTTP transport defined in spec revision 2025-03-26.

The attack primitive is trivial: an adversary submits a single HTTP POST whose body is a JSON array of N requests, where N is large (10³ to 10⁶). If the server dispatches each entry synchronously — commonly via `request.batch.forEach(handle)` or `body.map(process)` — it pays O(N) work for a single O(1) network cost. CPU, memory, and downstream rate-limiting budgets (for methods that themselves hit a database or a remote API) are amplified by N.

CometBFT issue #2867 is the canonical public instance of this primitive biting a production system. The Language Server Protocol community debated banning batching entirely in PR #1651 after repeated incidents. Neither venue is theoretical: the class is demonstrated, the fix is documented (enforce a max batch size, reject with code -32600), and the prevalence in MCP servers has not been measured.

## What an auditor must see (evidence contract)

A regulator reading a compliance report (EU AI Act Art. 15 on robustness, ISO 27001 A.8.23 on filtering) should be able to follow:

1. **Source**: the specific handler branch where an array-shaped JSON-RPC body enters the server (the `Array.isArray` guard or the batch-named iteration call).
2. **Sink**: the synchronous per-element dispatch call (forEach/map/for..of) that executes N method calls for a single request.
3. **Mitigation**: the presence or absence of a length check, rate limiter, `.slice(0, MAX)`, or `throttle` wrapper in the enclosing function.
4. **Impact**: DoS amplification scoped to the server host with trivial exploitability — one TCP connection, one JSON payload.

The finding is wrong if the enclosing function contains any of: `.length` compared to a numeric constant, a variable name containing "max", "limit", "throttle", or "rate", or a `.slice(...)` call on the batch before iteration.

## Why structural analysis, not regex

A regex for `Array.isArray` or `.forEach` fires on every array manipulation in a codebase — documentation parsers, UI utilities, test fixtures. The signal is in the *conjunction* of (1) a JSON-RPC-shaped guard, (2) iteration of that same array, (3) absence of a length-bounded mitigation in the enclosing function. That conjunction is a structural property of the AST, not a lexical property of the source text.

## Lethal edge cases (tests must cover)

- **batch-within-batch**: payload with a wrapper object whose `.batch` field is the array — the outer object has a length of 1, the inner array is unbounded.
- **map-without-guard**: `batch.map(handle)` anywhere in the file with `batch` being a parameter or variable whose name matches `/(batch|requests|messages)/i` and the enclosing function has no limit vocabulary.
- **notification-storm-via-batch**: array of request objects with no `id` field — the handler processes them without waiting for any response-mismatch check, so the amplification is pure write-side.
- **recursive-dispatch**: handler dispatches each entry by method name and the dispatched method itself recurses into sub-arrays.

## Confidence ceiling

Cap at 0.90. The rule cannot distinguish between "server has no batch limit anywhere" (true positive) and "server has a global rate limiter at the transport layer not visible in this source fragment" (false positive). 0.90 reflects that residual uncertainty while still qualifying the finding for audit-grade reporting.
