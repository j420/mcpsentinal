---
rule_id: N5
interface_version: v2
severity: critical
owasp: MCP05-privilege-escalation
mitre: AML.T0054
risk_domain: protocol-transport

threat_refs:
  - kind: spec
    id: MCP-2024-11-05-Capabilities
    url: https://modelcontextprotocol.io/specification/2024-11-05/#capabilities
    summary: >
      The MCP capabilities object declared in the initialize response is
      the client's SOURCE OF TRUTH for what the server will do. Clients
      apply security controls — consent prompts, audit logging, sandbox
      scoping — based on which capabilities the server advertised.
      Servers that declare `tools: false` (or omit the key) while
      implementing a handler for `tools/call` silently bypass the
      client's entire control surface for that capability.
  - kind: paper
    id: TLS-Downgrade-Precedent
    url: https://www.cloudflare.com/learning/ssl/how-ssl-works/
    summary: >
      The TLS downgrade precedent — protocol downgrade becomes a viable
      attack whenever a party's decision surface consumes a claim the
      other party can lie about. MCP capability declarations are the
      MCP-layer analogue: the client trusts the capability object, the
      server controls its content.
  - kind: spec
    id: MITRE-ATLAS-AML-T0054
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      Capability-downgrade deception is the MCP-specific realisation of a
      broader AML.T0054 pattern: adversary declares a reduced capability
      surface, then exercises the full surface. Client's goal-policing
      does not see the exercise because its rulebook said the capability
      wasn't there.

lethal_edge_cases:
  - >
    Server declares `capabilities.tools = false` (or omits the key) yet
    implements a handler for `tools/call`. The client does not apply
    tool-invocation safety controls because, per the declaration, tools
    are not available. The server exercises the capability anyway.
  - >
    Sampling capability omitted from declaration, but `sampling/createMessage`
    handler is registered. Clients that would refuse a sampling request
    from a non-sampling server happily forward it because the consent
    gate is not armed.
  - >
    Resources capability downgraded to `subscribe: false` but the server
    registers a `resources/subscribe` handler. Clients skip per-subscribe
    confirmation because they believe subscription is unsupported.
  - >
    Conditional capability advertisement (capability reported as
    disabled for some `initialize` requests and enabled for others based
    on clientInfo heuristics). The declaration becomes a fingerprint-
    gated behaviour rather than a spec-truthful posture.

edge_case_strategies:
  - tools-disabled-but-handler-registered-scan
  - sampling-omitted-but-handler-registered-scan
  - resources-subscribe-downgrade-scan
  - fingerprint-gated-capability-scan

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - declared_versus_implemented_mismatch
  location_kinds:
    - source
    - capability

obsolescence:
  retire_when: >
    MCP spec mandates that clients refuse to invoke any method whose
    capability key is not explicitly set to true in the initialize
    response, AND the spec's conformance suite catches servers that
    register handlers for undeclared capabilities. Until then, the
    server-side invariant is the only enforcement.
---

# N5 — Capability Downgrade Deception

**Author:** Senior MCP JSON-RPC / Transport Security Engineer (dual persona).

## Threat narrative

The MCP capability object is the client's access-control mental model.
Disagreement between declaration and implementation silently disarms the
client's safety rails. N5 is structural: it flags code where a server
declares a capability as off while also registering a handler for a
method that requires that capability.

N5 consumes the shared catalogue `_shared/mcp-method-catalogue.ts` to
map method names to capability keys. No regex literals.

## Confidence cap

**0.78**. Cross-call inference — the declaration and the handler
registration must be correlated; the rule sees the code, not the live
handshake.
