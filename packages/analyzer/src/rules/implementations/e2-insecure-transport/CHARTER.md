---
rule_id: E2
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: CWE-319
    url: https://cwe.mitre.org/data/definitions/319.html
    summary: >
      CWE-319: Cleartext Transmission of Sensitive Information. The
      canonical CWE for http:// and ws:// transport carrying
      credentials or other sensitive data. An MCP server that
      transports tool invocations in plaintext inherits CWE-319
      directly — the first tool that passes a token is the first
      leak event.
  - kind: spec
    id: OWASP-MCP07-Insecure-Configuration
    url: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    summary: >
      OWASP MCP Top 10 MCP07 — Insecure Configuration. Explicitly
      enumerates plaintext transport as a Tier-1 misconfiguration.
  - kind: spec
    id: MCP-Spec-Transport-2025-03-26
    url: https://modelcontextprotocol.io/docs/concepts/transports
    summary: >
      MCP specification 2025-03-26 transport section. Streamable HTTP
      transport is the primary production surface. Production
      deployments are expected to layer TLS (https:// / wss://). An
      unencrypted transport is out of spec for network-exposed servers.
  - kind: spec
    id: RFC-8446-TLS-1.3
    url: https://datatracker.ietf.org/doc/html/rfc8446
    summary: >
      TLS 1.3 (RFC 8446). The baseline transport confidentiality
      control the E2 rule assumes production servers deploy.
  - kind: paper
    id: Firesheep-2010
    url: https://codebutler.com/projects/firesheep/
    summary: >
      Firesheep demonstrated in 2010 that cleartext HTTP session
      cookies on public WiFi were trivially stealable by any co-located
      observer. The same argument applies to MCP over http/ws: any
      token or credential embedded in a tool invocation is visible to
      a network observer.

lethal_edge_cases:
  - >
    stdio transport is NOT network-exposed. An MCP server over stdio
    does not transit the network and is out of E2's scope. The rule
    fires only on transport values in the insecure-network set
    (http, ws). stdio / https / wss silently do not fire.
  - >
    Localhost + plaintext. An MCP server over http://127.0.0.1:N is
    still in scope — DNS rebinding makes cleartext localhost traffic
    reachable. Same signal class as E1; E2 fires on the transport
    attribute regardless of bind address.
  - >
    Mixed http+https deployment. Some servers expose the same MCP
    endpoint on both http and https for "compatibility". The scanner's
    connection_metadata reports the transport it actually connected
    via. If it connected via http, E2 fires; a sibling https endpoint
    does not dismiss the finding — the http one remains exploitable.
  - >
    connection_metadata is null. Rule must silently skip — cannot
    assert transport security without a live connection observation.
  - >
    Custom transport strings. A deployment may use a custom transport
    label ("grpc-insecure", "quic-no-tls"). The rule's insecure set is
    deliberately small (http, ws) — expansion requires explicit
    charter amendment. Unknown transport strings do NOT fire (refuse
    to guess).

edge_case_strategies:
  - exact-transport-match
  - null-connection-skip
  - explicit-insecure-set

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - plaintext_transport_observed
  location_kinds:
    - capability
    - config

obsolescence:
  retire_when: >
    The MCP specification forbids the use of http:// and ws:// for any
    network transport AND every MCP client implementation refuses to
    connect to a non-TLS URL. Under those conditions E2's attack surface
    is extinguished.
---

# E2 — Insecure Transport (HTTP/WS)

**Author:** Senior MCP Supply-Chain Researcher + Senior MCP Security Engineer.
**Applies to:** Any MCP server for which the scanner captured
`context.connection_metadata` and the transport is an exact member of the
insecure set {http, ws}.

## Confidence cap: 0.85

High confidence — transport observation is direct. The 0.15 head-room is
reserved for intentional test/dev deployments and for the case where the
transport string is a custom label the scanner misinterprets.

## Relationship to E1

E1 (no auth) and E2 (plaintext) commonly fire together. They are orthogonal
— an authenticated server over http still leaks the authenticated session;
an authentication-less https server is unauthenticated but at least not
observable to passive listeners.
