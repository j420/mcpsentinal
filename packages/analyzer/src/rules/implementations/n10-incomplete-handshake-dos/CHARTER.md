---
rule_id: N10
name: Incomplete Handshake Denial of Service
interface_version: v2
severity: high
owasp: MCP07-insecure-config
mitre: AML.T0054
risk_domain: denial-of-service
threat_refs:
  - kind: spec
    id: MCP-2025-03-26-lifecycle
    url: https://modelcontextprotocol.io/specification/2025-03-26/basic/lifecycle
    summary: "MCP spec 2025-03-26 defines a strict lifecycle: clients MUST send initialize before issuing functional requests. The spec does not mandate a server-side handshake timeout, so an attacker can open a connection, never send initialize, and hold a server slot indefinitely."
  - kind: paper
    id: CWE-400-resource-exhaustion
    url: https://cwe.mitre.org/data/definitions/400.html
    summary: "CWE-400 Uncontrolled Resource Consumption. The MCP variant is a Slowloris-class attack: many connections, no initialize, no timeout — the connection pool exhausts."
  - kind: incident
    id: Slowloris
    url: https://en.wikipedia.org/wiki/Slowloris_(cyber_attack)
    summary: "Slowloris is the canonical precedent: open TCP, send bytes at the minimum rate to avoid idle timeout, hold server slots. HTTP servers fixed this with per-header timeouts; MCP has not fixed it at the spec level."
lethal_edge_cases:
  - id: websocket-no-deadline
    description: "wss.on('connection', socket => socket.on('message', handleInit)) — the server waits for the initialize message indefinitely. An attacker opens connections and never sends."
  - id: http-server-no-maxConnections
    description: "http.createServer(handler) without server.maxConnections set and without per-socket timeout — a textbook slowloris target."
  - id: streamable-http-no-session-timeout
    description: "Streamable HTTP transport retains session state across multiple requests; without a per-session handshake deadline, half-open sessions persist until process restart."
  - id: initialise-inside-loop-no-deadline
    description: "while (!initialized) { await socket.read(); ... } with no timeout or max-iteration — the read blocks forever, consuming a worker."
edge_case_strategies:
  - accept_connection_without_handshake_timeout
  - listen_without_maxconnections_and_without_timeout
  - websocket_server_without_deadline_on_initialize
evidence_contract:
  minimum_chain:
    source: true        # the connection-accept site (createServer / WebSocketServer / listen)
    sink: true          # the handshake read path with no deadline
    mitigation: true    # MUST report presence/absence of a per-connection handshake timeout
    impact: true        # resource-exhaustion (Slowloris class) scoped to the MCP host
  required_factors:
    - handshake_deadline_absent
  location_kinds:
    - source
obsolescence:
  retire_when: "MCP spec mandates a handshake deadline (e.g. 30s) AND mainstream MCP SDKs enforce it by default with a configurable override."

mutations_survived: []
mutations_acknowledged_blind: []
---

# N10 — Incomplete Handshake Denial of Service

## Threat narrative

The MCP lifecycle (spec 2025-03-26) says clients MUST send an `initialize` request before any functional request. It does NOT mandate a server-side deadline on that initialize. Left unguarded, this reproduces Slowloris (CWE-400): an attacker opens N connections to the MCP server and never sends the initialize message. Each connection consumes a file descriptor, a connection-tracking entry, and (on WebSocket/SSE) a heartbeat worker. At the default ulimit, the service is unreachable within seconds.

The fix is trivial — `AbortSignal.timeout(30_000)` around the initialize read, `http.Server.headersTimeout`, `http.Server.requestTimeout`, `ws` server `handshakeTimeout` option. None of these ship on by default. A source-code scan for the accept path + absence of a deadline is a high-quality signal.

## Evidence contract

1. **Source**: the connection-accept site — `createServer`, `WebSocketServer`, `http.createServer`, `net.createServer`, or `app.listen`.
2. **Sink**: the handshake read — the await on `initialize` or equivalent lifecycle gate.
3. **Mitigation**: absence of timeout vocabulary (`setTimeout`, `handshakeTimeout`, `headersTimeout`, `requestTimeout`, `AbortSignal.timeout`, `Promise.race`, `maxConnections`) in the enclosing function.
4. **Impact**: trivial DoS scoped to the server host.

## Lethal edge cases

- **websocket-no-deadline**: WebSocketServer listens for the initialize message with no handshake timeout option.
- **http-server-no-maxConnections**: `http.createServer(handler).listen(port)` with no `server.maxConnections`, no `requestTimeout`, no `headersTimeout`.
- **streamable-http-no-session-timeout**: session handshake phase has no deadline; half-open sessions persist.
- **initialise-inside-loop-no-deadline**: `while (!initialized) await read()` with no timeout.

## Confidence ceiling

Cap at 0.82. Some deployments sit behind a reverse proxy that enforces the timeout at the edge; the rule cannot see that configuration from source alone. The ceiling reflects that residual uncertainty.
