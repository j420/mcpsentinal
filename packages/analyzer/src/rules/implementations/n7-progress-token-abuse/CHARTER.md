---
rule_id: N7
name: Progress Token Prediction and Injection
interface_version: v2
severity: high
owasp: MCP07-insecure-config
mitre: AML.T0054
risk_domain: protocol-transport
threat_refs:
  - kind: spec
    id: MCP-2025-03-26-progress
    url: https://modelcontextprotocol.io/specification/2025-03-26/basic/utilities/progress
    summary: "MCP spec 2025-03-26 §5.1 defines progressToken as an opaque identifier supplied by the requester and echoed by the server in notifications/progress. The spec does not mandate server-side unpredictability, so naive implementations expose this identifier to guess-and-inject attacks."
  - kind: cve
    id: CVE-2025-6515
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-6515
    summary: "oatpp-mcp session id prediction. The defect class — predictable identifier used for cross-request correlation — applies to progressTokens when generated from user input or a sequential counter."
  - kind: paper
    id: MCP-progress-injection-note
    url: https://modelcontextprotocol.io/specification/2025-03-26/basic/utilities/progress
    summary: "When a server accepts progressToken from request params without ownership validation (checking the token was issued for the caller's session), any client on the same transport can inject fake progress notifications targeting another session."
lethal_edge_cases:
  - id: user-controlled-token
    description: "Server sets `progressToken = req.body.progressId` — the attacker fully controls the correlation key. Progress notifications can be sent for arbitrary sessions."
  - id: sequential-counter
    description: "Server increments a global counter (`progressToken = ++this._progress`) — predictable ids allow race-spoofing."
  - id: date-now-token
    description: "progressToken = Date.now() — predictable within a 1ms window."
  - id: index-as-token
    description: "Token derived from array index (`progressToken = items.indexOf(x)`) — deterministic and enumerable."
edge_case_strategies:
  - progress_token_from_user_input
  - progress_token_from_counter
  - progress_token_from_timestamp
evidence_contract:
  minimum_chain:
    - source
    - propagation
    - sink
    - impact
  required_factors:
    - weak_progress_token_source
  location_kinds:
    - source_code_line
obsolescence:
  retire_when: "MCP spec mandates unpredictable progressToken generators AND MCP clients validate token ownership against active request maps before accepting notifications/progress payloads."
---

# N7 — Progress Token Prediction and Injection

## Threat narrative

The MCP spec (2025-03-26) introduces a `progressToken` parameter a client can attach to a long-running request; the server echoes the token in `notifications/progress` payloads so the client can associate streaming progress with the originating request. The spec does not mandate token unpredictability and says nothing about ownership validation.

Two concrete attacks exploit this. First, if the server uses `req.body.progressToken` directly as the correlation key — i.e. trusts the client-provided value without rebinding — any client on the same transport can inject fake progress notifications for another session by guessing or observing the target's token. Second, if the server generates tokens with a sequential counter or a timestamp, the tokens are predictable enough to enumerate without any prior observation.

Both failures share the source-propagation pattern: an un-cryptographic, untrusted value reaches the progress-correlation field. The detection follows the AST: any variable declaration or assignment whose identifier matches `progress(Token|Id|Key|Counter)` and whose RHS is either a user-input expression (`req.body.*`, `params.*`, `query.*`) or a predictable generator (`++counter`, `Date.now`, `.indexOf`, integer literal) and whose enclosing function does not also call `crypto.randomUUID`/`randomBytes`/`uuid`/`nanoid`.

The legacy implementation of this rule (living under the wrong id "N3" in the pre-migration tree) covered the user-input arm but not the predictable-generator arm. This migration covers both.

## Evidence contract

1. **Source**: the expression that produces the progress token (user parameter OR predictable generator).
2. **Propagation**: the assignment that writes the token into the progress-correlation field.
3. **Sink**: a `sendNotification`/`notifications/progress`/`notify`/`progress` call that emits the predictable/attacker-controlled token on the wire.
4. **Impact**: session-hijack or DoS (injecting progress for a never-terminating request) with moderate to trivial exploitability depending on source kind.

## Lethal edge cases

- **user-controlled-token**: `const progressToken = req.body.progressId;`
- **sequential-counter**: `progressToken = ++this._progressCounter;`
- **date-now-token**: `progressToken = Date.now();`
- **index-as-token**: `progressToken = items.indexOf(x);`

## Confidence ceiling

Cap at 0.88. User-input arm is more damning than predictable-generator arm; the ceiling permits the former to report near the top of the range while the latter stays mid-band.
