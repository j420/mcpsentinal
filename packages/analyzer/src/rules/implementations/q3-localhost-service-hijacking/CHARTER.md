---
rule_id: Q3
interface_version: v2
severity: critical

threat_refs:
  - kind: spec
    id: OWASP-MCP07
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 — MCP07 Insecure Configuration. An MCP server
      listening on 127.0.0.1 or 0.0.0.0 without authentication is
      reachable from any process running as the same user. Browser
      DNS rebinding gives websites the ability to reach 127.0.0.1
      services too, extending the reach beyond the local user.
  - kind: spec
    id: CWE-306
    url: https://cwe.mitre.org/data/definitions/306.html
    summary: >
      CWE-306 — Missing Authentication for Critical Function. The
      MCP tool-invocation surface is a critical function; a server
      binding an HTTP or WebSocket listener to localhost without
      any auth check exposes the full tool set to any local
      process or DNS-rebinding site.
  - kind: paper
    id: DNS-REBINDING-PRIMER
    url: https://portswigger.net/research/dns-rebinding-attacks
    summary: >
      PortSwigger DNS rebinding primer. Documents how a website can
      resolve a short-TTL hostname to 127.0.0.1 mid-session and
      send requests to local services. Unauthenticated localhost
      MCP servers are the highest-value target class for rebinding.

lethal_edge_cases:
  - >
    HTTP server on 127.0.0.1 without auth — `http.createServer(...)`
    + `.listen(port, "127.0.0.1")` with no request-header check
    inside the handler for a bearer token / shared secret.
  - >
    Bind to 0.0.0.0 — same risk as localhost plus LAN exposure.
    The classification vocabulary treats 0.0.0.0 as a localhost-
    class bind because the absence-of-auth failure mode is
    identical.
  - >
    WebSocket server without a handshake secret — `new
    WebSocketServer({ port })` then `ws.on("connection", ...)` with
    no `origin` or token validation.
  - >
    MCP-specific mention — the bound server is claimed to be an
    MCP server in the receiver or property name (`mcpServer`,
    `tools`, `server`). When those tokens co-occur with the bind,
    confidence is amplified because the rule is no longer
    speculating that the bound service carries MCP tool calls.

edge_case_strategies:
  - shared-localhost-sinks-vocabulary  # DATA_EXFIL_SINKS localhost-port kind
  - listen-bind-ast-match              # .listen / .bind on loopback arg
  - auth-token-scope-suppression       # authorization / bearer / sharedSecret identifier in scope
  - skip-when-no-network-binding       # honest-refusal gate: no fs.listen or .listen found

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - localhost_bind_observed
    - no_auth_in_scope
  location_kinds:
    - source

obsolescence:
  retire_when: >
    The MCP spec mandates mutual-auth for every transport (stdio
    included), OR every ecosystem client runtime refuses to speak
    to a localhost MCP endpoint that has not presented a signed
    session token. Neither exists as of 2026-04.

mutations_survived:
  - unicode-homoglyph-identifier
mutations_acknowledged_blind:
  - split-string-literal
  - base64-wrap-payload
---

# Q3 — Localhost MCP Service Hijacking

## Threat Model

A typical MCP-over-HTTP example binds a server to `127.0.0.1:3000`
with no authentication. Any local process (or a DNS-rebinding
website loaded in the user's browser) can enumerate the tools
and invoke them. The attacker does not need to compromise the
user's account — they only need to run code on the same host or
trick the browser into resolving a short-TTL hostname to
loopback.

## Detection Strategy — AST Listener Match

Q3 searches the AST for every call of `.listen(port, host?)` or
`.bind(host, port)` where the host argument matches the localhost
vocabulary (`127.0.0.1`, `"localhost"`, `0.0.0.0`) OR the call
receiver / property path mentions an MCP token (`mcpServer`,
`tools`, `server`). It then walks the enclosing scope looking
for an auth identifier (`authorization`, `bearer`, `token`,
`sharedSecret`). If any is present, the finding is demoted.

If no network-binding call appears anywhere in the source code,
the rule returns `[]` — the honest-refusal gate for this rule.

## Confidence Cap

**0.75** — two common false positives: a localhost health-check
endpoint that has no sensitive routes, and a localhost-only
admin dashboard whose handler validates auth inside the route
rather than in a visible middleware. The cap holds reviewer
headroom for both cases.
