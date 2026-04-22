---
rule_id: N11
interface_version: v2
severity: critical
owasp: MCP07-insecure-config
mitre: AML.T0054
risk_domain: protocol-transport

threat_refs:
  - kind: spec
    id: MCP-Protocol-Versions
    url: https://modelcontextprotocol.io/specification/versioning
    summary: >
      The MCP initialize handshake includes a `protocolVersion` field.
      Clients and servers negotiate the effective version. The 2024-11-05
      baseline does NOT support tool annotations; the 2025-03-26 revision
      adds readOnlyHint / destructiveHint / idempotentHint / openWorldHint
      and the Streamable HTTP transport; 2025-06-18 adds elicitation and
      roots; 2025-11-25 adds further refinements. A server that accepts
      an older version than it could speak loses those security features
      silently.
  - kind: paper
    id: TLS-Downgrade-Precedent
    url: https://tools.ietf.org/html/rfc8446
    summary: >
      TLS 1.3 mandates downgrade protection precisely because the TLS 1.2
      record layer was vulnerable to a negotiation rollback. MCP
      inherited the same architectural shape (negotiate at the top of
      the connection) without the same protection. N11 targets servers
      that accept older protocol versions without rejecting obvious
      downgrade attempts.
  - kind: spec
    id: MITRE-ATLAS-AML-T0054
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      Version downgrade is AML.T0054 at the protocol layer: by selecting
      an older protocol, the adversary removes the newer safety controls
      (annotations, per-call metadata). The rule flags servers whose
      negotiation path is built to accept any client-proposed version.

lethal_edge_cases:
  - >
    Server's initialize handler reads `req.params.protocolVersion` and
    reflects it back in the response without comparison to a minimum
    acceptable version. Client proposes `2024-01-01` (pre-baseline)
    and the server agrees, dropping every feature added since.
  - >
    Server uses `minProtocolVersion = '2024-11-05'` but never actually
    rejects requests below it — the variable is declared, used nowhere.
    The downgrade still occurs; the variable is security theatre.
  - >
    Version comparison uses string `<` / `>` which lexicographically
    sorts `2024-11-05` AFTER `2025-03-26` only by chance. Year-month-
    day ordering works until a 4-digit year / 2-digit month collision;
    any custom comparator must use the SPEC_VERSION_ORDER table to be
    correct.
  - >
    Server explicitly accepts ANY version claimed by the client
    (`response.protocolVersion = req.params.protocolVersion`). This is
    the anti-pattern the rule targets as the most reliable indicator
    of willful downgrade acceptance.

edge_case_strategies:
  - initialize-version-echo-scan
  - min-version-declared-not-enforced-scan
  - string-lexicographic-compare-scan
  - any-version-accept-scan

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - version_enforcement_absent
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP SDKs ship with a default minProtocolVersion that developers must
    explicitly opt out of; SDKs refuse to negotiate versions older than
    the minimum even if the developer's code requests it.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# N11 — Protocol Version Downgrade Attack

Structural. Uses the shared MCP method catalogue's SPEC_VERSION_ORDER.
Confidence cap 0.85.
