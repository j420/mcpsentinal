---
rule_id: N3
name: JSON-RPC Request ID Collision
interface_version: v2
severity: high
owasp: MCP07-insecure-config
mitre: AML.T0054
risk_domain: protocol-transport
threat_refs:
  - kind: spec
    id: JSONRPC-2.0-SEC-4.1
    url: https://www.jsonrpc.org/specification#request_object
    summary: "JSON-RPC 2.0 Section 4.1 states that Request id MUST be unique within a session. Sequential integer counters are 'unique within the session' in the narrow sense but are also entirely predictable, which enables response spoofing on any transport with more than one producer."
  - kind: cve
    id: CVE-2025-6515
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-6515
    summary: "Session ID prediction vulnerability in oatpp-mcp. The underlying defect class is 'predictable identifier used for request/response correlation'. The same primitive applies to JSON-RPC request IDs when generated via sequential counter instead of cryptographic UUID."
  - kind: paper
    id: JSON-RPC-response-spoofing-class
    url: https://www.jsonrpc.org/specification#response_object
    summary: "The JSON-RPC Response object echoes the request id. If an attacker on the same transport can predict the next id, they can race a forged response past the legitimate server, causing the client to honour an adversary-controlled reply (confused deputy)."
lethal_edge_cases:
  - id: id-wraparound
    description: "Counter implemented as 32-bit integer wraps to 0 after 2^31 - 1 requests; a long-lived session re-uses ids predictably, enabling collision attacks that skip the initial guess phase."
  - id: post-increment-in-template-literal
    description: "`this._request_id += 1; payload.id = this._request_id` — two-statement form where a simple regex for `id++` misses the assignment but the integer sequence is identical."
  - id: date-now-as-id
    description: "`id: Date.now()` looks random but is millisecond-predictable and monotonic. An attacker with any clock-sync can enumerate the next id within a 1ms window."
  - id: increment-in-property-initializer
    description: "Class field initialiser `id = this.counter++` — the counter is a member, the increment lives in the object construction path and a flat textual scan misses it."
edge_case_strategies:
  - counter_increment_assigned_to_id
  - date_now_assigned_to_id
  - integer_literal_assigned_to_id
evidence_contract:
  minimum_chain:
    source: true        # assignment of a predictable expression to an id identifier
    propagation: true   # token flows from RHS to the outbound JSON-RPC payload
    sink: true          # id reaches the wire as the correlation key
    mitigation: true    # MUST report presence/absence of crypto random generator
    impact: true        # response spoofing (CVE-2025-6515 class)
  required_factors:
    - predictable_request_id_generator
  location_kinds:
    - source
obsolescence:
  retire_when: "All major MCP SDKs default to crypto.randomUUID() for request ids AND the spec mandates unpredictable ids in a future revision."

mutations_survived: []
mutations_acknowledged_blind: []
---

# N3 — JSON-RPC Request ID Collision

## Threat narrative

JSON-RPC 2.0 uses the `id` field to correlate requests and responses. The spec requires only that ids be unique within a session — it does not require unpredictability. A naive implementation uses a sequential integer counter (`let requestId = 0; payload.id = ++requestId`) or a timestamp (`id: Date.now()`). Both are monotonic and predictable.

Predictable request ids enable response spoofing. On any transport where an adversary can inject bytes into the client's receive stream (compromised MitM, colocated SSE producer, Streamable HTTP multi-writer), the attacker can forge a response whose id matches the client's next pending request. The client dispatches the forged payload to the original request's callback. This is the same primitive as CVE-2025-6515 (oatpp-mcp session-id prediction); the defect class is identical.

The cryptographic mitigation is trivial — `crypto.randomUUID()`, `crypto.randomBytes()`, `nanoid()`. Implementations that skip it do so out of inertia, not constraint. The rule detects the inertia pattern: any assignment to an identifier whose name is `requestId`, `request_id`, `rpcId`, `messageId`, `_request_id`, `_id` where the right-hand side is a counter expression, a `Date.now()`, or an integer literal, and no cryptographic generator appears in the enclosing function.

## Evidence contract

1. **Source**: the specific line where the request id is generated, with the observed expression captured.
2. **Sink**: the message emission site (the code that sends the request on the wire carrying the predictable id).
3. **Mitigation**: absence check for `crypto.randomUUID`, `crypto.randomBytes`, `uuid*`, `nanoid`, `cuid` in the enclosing scope.
4. **Impact**: session-hijack / response-spoofing primitive with moderate exploitability (requires a co-located producer or MitM).

## Lethal edge cases (tests cover)

- **id-wraparound**: 32-bit counter overflows after 2³¹−1 requests; long-lived sessions re-use ids.
- **post-increment-in-template-literal**: `this._request_id += 1; payload.id = this._request_id` — two-statement form.
- **date-now-as-id**: `id: Date.now()` — timestamp-monotonic, not unpredictable.
- **increment-in-property-initializer**: class field `private id = this.counter++` — the AST node is a PropertyDeclaration, not a textual `id++` match.

## Confidence ceiling

Cap at 0.85. Some servers intentionally use sequential ids for debuggability and pair that with transport-layer unique-session isolation (e.g. a fresh TCP connection per logical session, TLS authenticating both peers). The rule cannot confirm or deny that envelope, so the ceiling reflects the residual false-positive risk from misclassifying a properly-isolated sequential counter as exploitable.
