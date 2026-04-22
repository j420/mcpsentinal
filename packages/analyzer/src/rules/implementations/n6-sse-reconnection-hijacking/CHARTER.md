---
rule_id: N6
interface_version: v2
severity: critical
owasp: MCP07-insecure-config
mitre: AML.T0061
risk_domain: protocol-transport

threat_refs:
  - kind: cve
    id: CVE-2025-6515
    summary: >
      MCP Streamable HTTP session-hijacking-class vulnerability. A
      session identifier propagated via URI without integrity binding
      permitted attackers to replay / predict session ids and hijack
      existing SSE connections. N6 detects the server-side code shape
      that enables this class — reconnection paths that do not re-
      authenticate, and Last-Event-ID handling that does not validate
      integrity.
  - kind: spec
    id: MCP-2025-03-26-Streamable-HTTP
    url: https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#streamable-http
    summary: >
      The Streamable HTTP transport (introduced in the 2025-03-26 MCP
      spec) inherits the SSE reconnection semantics from HTML5 Server-
      Sent Events. Reconnection is automatic and carries `Last-Event-ID`
      — the spec does not mandate re-authentication, leaving the server
      responsible for session integrity. N6 targets servers that accept
      the spec's default without adding the integrity check.
  - kind: spec
    id: HTML5-EventSource
    url: https://html.spec.whatwg.org/multipage/server-sent-events.html#the-eventsource-interface
    summary: >
      HTML5 EventSource reconnection is designed around cooperative
      clients. A trusted client replays Last-Event-ID to resume its own
      stream; a malicious client can replay a captured Last-Event-ID
      to take over a victim's stream if the server does not bind event
      ids to session identity.

lethal_edge_cases:
  - >
    EventSource reconnection without re-authentication. The server's
    `reconnect` / `retry` handler reads the incoming Last-Event-ID and
    resumes the stream without verifying the caller's credentials. An
    attacker who captured a prior Last-Event-ID (from a log, a proxy,
    or a session-id leak) takes over the victim's stream.
  - >
    Last-Event-ID parsed with `parseInt` / `Number` without integrity
    signature. The id is used to look up the resume point directly. No
    HMAC / signed-envelope check. Attacker-crafted ids steer the resume
    target.
  - >
    Session identifier exposed in URL or response header without
    signing. The URL path contains the session id, or a response
    includes `X-Session-Id: <raw>` without an accompanying HMAC. Network
    intermediaries can read the id and impersonate the session.
  - >
    Reconnection code reads Last-Event-ID and forwards it to an
    underlying store query (e.g. `events.slice(lastEventId)`) without
    bounds checking. The attacker can walk arbitrary offsets of the
    event log.

edge_case_strategies:
  - eventsource-reconnect-no-auth-scan
  - last-event-id-no-integrity-scan
  - session-id-in-url-scan
  - event-log-unbounded-offset-scan

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - reconnect_auth_absent
  location_kinds:
    - source

obsolescence:
  retire_when: >
    The MCP spec mandates that Streamable HTTP reconnection requires a
    client-authenticated token that is re-verified on every resume,
    AND mainstream SDKs implement this by default. Until then, server-
    side defence is primary.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# N6 — SSE Reconnection Hijacking

Deterministic, structural. Skips test files. Confidence cap 0.80.

Zero regex literals; lexicon in `./data/sse-surfaces.ts`.
