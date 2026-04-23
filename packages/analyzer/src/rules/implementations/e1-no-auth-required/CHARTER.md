---
rule_id: E1
interface_version: v2
severity: medium

threat_refs:
  - kind: spec
    id: OWASP-ASVS-V2
    url: https://owasp.org/www-project-application-security-verification-standard/
    summary: >
      OWASP Application Security Verification Standard v4.0.3 — V2
      Authentication Verification Requirements. V2.1 (general) requires
      that all access to any application feature not explicitly public
      MUST require authentication. An MCP server that accepts
      initialize + tools/list without any authentication is trivially
      non-conformant.
  - kind: spec
    id: OWASP-MCP07-Insecure-Configuration
    url: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    summary: >
      OWASP MCP Top 10 MCP07 — Insecure Configuration. Explicitly calls
      out "MCP server exposes tool enumeration or invocation without
      authentication" as a Tier-1 misconfiguration.
  - kind: spec
    id: MCP-Spec-Authorization-2025-06
    url: https://modelcontextprotocol.io/docs/concepts/authorization
    summary: >
      MCP Authorization specification (adopted mid-2025). Remote MCP
      servers SHOULD implement OAuth 2.0 (RFC 9700) or an equivalent
      authenticated scheme. Production deployments without any auth
      are out of spec conformance.
  - kind: paper
    id: DNS-Rebinding-2007
    url: https://crypto.stanford.edu/dns/dns-rebind.pdf
    summary: >
      Jackson, Bortz, Boneh "Protecting Browsers from DNS Rebinding
      Attacks" (CCS 2007). Establishes that localhost-bound HTTP
      services without authentication are reachable by ANY web page a
      user visits via DNS rebinding. An unauthenticated MCP server
      listening on 127.0.0.1 is exactly this threat model.
  - kind: spec
    id: ISO-27001-A.5.16
    url: https://www.iso.org/standard/82875.html
    summary: >
      ISO/IEC 27001:2022 Annex A Control 5.16 — Identity Management.
      Requires registered identities for all access to information
      and other associated assets. An unauthenticated MCP endpoint
      has no registered identity.

lethal_edge_cases:
  - >
    Localhost-only binding is NOT a substitute for auth. Many MCP
    servers bind to 127.0.0.1 and assume that is sufficient. DNS
    rebinding makes localhost reachable from any tab in the user's
    browser. The rule fires on auth_required=false regardless of
    transport or bind address; the localhost assumption is called
    out in the impact narrative.
  - >
    stdio transport. An MCP server running over stdio (the process
    launches the server and pipes to it) inherits the parent process's
    security boundary. For stdio-launched servers E1 is arguably not
    material — the parent process is the authentication. The
    connection metadata populated by the scanner only reaches E1 when
    a live network connection was made; for stdio-only servers E1
    skips silently (connection_metadata=null).
  - >
    "auth_required: false" but auth happens at a higher layer. Some
    deployments front the MCP server with a reverse proxy that
    terminates OAuth before the request reaches the server. The
    scanner cannot see the proxy; a false positive is possible. The
    verification step explicitly instructs the reviewer to confirm
    proxy-layer auth before dismissing.
  - >
    connection_metadata is null. When no live connection was made,
    the rule cannot assert anything about the runtime auth posture.
    It MUST skip silently (AnalysisCoverage records the gap).
  - >
    auth_required=true but auth is trivially bypassable. The scanner
    observes whether the server rejects unauthenticated connections,
    not whether the auth itself is strong. This rule does NOT cover
    weak-auth cases — that is outside E1's surface (H1 covers OAuth
    specifically; K6/K7/K8 cover token lifecycle).

edge_case_strategies:
  - null-connection-skip
  - localhost-does-not-count
  - proxy-layer-reviewer-note

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - no_auth_confirmed_runtime
  location_kinds:
    - capability
    - config

obsolescence:
  retire_when: >
    The MCP specification makes authentication MANDATORY for any
    network transport (removing the "SHOULD" qualifier from the
    authorization spec) AND the reference client refuses to connect to
    an unauthenticated server. Under those conditions the unauth
    posture is impossible to reach production.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# E1 — No Authentication Required

**Author:** Senior MCP Supply-Chain Researcher + Senior MCP Security Engineer.
**Applies to:** Any MCP server for which the scanner captured
`context.connection_metadata` from a live connection attempt.

## Confidence cap: 0.85

High confidence — the observation is direct (connected, initialize + tools/list
without credentials succeeded). The 0.15 head-room covers:
- reverse-proxy-terminated auth that the scanner cannot see;
- intentional unauthenticated servers (public read-only registries);
- dev/testing deployments explicitly meant to be unauth.

## Relationship to H1 (OAuth) and K6-K8 (credential lifecycle)

E1 detects "no auth at all". H1 detects "OAuth-based auth but implemented
unsafely" (RFC 9700 violations). K6-K8 detect "auth exists but tokens are
poorly scoped / not rotated / shared across boundaries". All four rules
can fire on the same server — they cover orthogonal failure modes.
