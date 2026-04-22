---
rule_id: I15
interface_version: v2
severity: high

threat_refs:
  - kind: cve
    id: CVE-2025-6515
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-6515
    summary: >
      MCP Streamable HTTP session hijacking via URI manipulation
      (oatpp-mcp session-id prediction class). Demonstrated that
      weak session-token generation and inadequate session-binding
      are in-the-wild exploitable against MCP Streamable HTTP
      transport.
  - kind: spec
    id: MCP-StreamableHTTP-2025-03-26
    url: https://modelcontextprotocol.io/specification/2025-03-26/basic/transports
    summary: >
      MCP 2025-03-26 added Streamable HTTP transport. Sessions
      authenticate ongoing client-server communication. Weak
      session management at the application layer defeats the
      transport's integrity goals.

lethal_edge_cases:
  - >
    Session token seeded from Math.random() — cryptographically
    insecure; predictable with enough samples. CVE-2025-6515 pattern
    class.
  - >
    Session token seeded from Date.now() — monotonic + knowable with
    rough clock knowledge.
  - >
    UUID v1 session tokens — encode MAC address + timestamp; leak
    machine identity and are monotonic.
  - >
    Session cookies with secure: false — cookie transmitted over
    plain HTTP on any downgrade path.
  - >
    Session cookies with httpOnly: false — cookie readable from
    JavaScript; XSS exfiltration primitive.

edge_case_strategies:
  - anti-pattern-catalogue
  - token-trigram-scan
  - cookie-flag-scan
  - source-line-citation
  - cwe-mapped-factor

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - session_anti_pattern_matched
    - charter_confidence_cap
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP Streamable HTTP transport spec mandates crypto.randomUUID
    session generation and secure+httpOnly cookies at the protocol
    layer, not the application layer.
---

# I15 — Transport Session Security

Detects weak session management patterns in MCP Streamable HTTP
transport sources. Uses the shared `SESSION_ANTI_PATTERNS` catalogue;
each entry has a token trigram plus a CWE attribution. Confidence
cap **0.85** — the trigram is exact-match but presence in code does
not prove production use.
