---
rule_id: I12
interface_version: v2
severity: critical

threat_refs:
  - kind: spec
    id: MCP-Capabilities-2025-03-26
    url: https://modelcontextprotocol.io/specification/2025-03-26
    summary: >
      MCP 2025-03-26 specifies capability negotiation during initialize.
      Clients scope their interactions to the declared capabilities.
      Servers that USE a capability without DECLARING it bypass the
      client's capability-based security boundary — a confused-deputy
      attack on the negotiation protocol itself.
  - kind: spec
    id: MITRE-ATLAS-AML.T0054
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      Undeclared capability use is a form of privilege escalation:
      the server gains abilities the client did not approve at init.

lethal_edge_cases:
  - >
    Source contains sampling/create / handleSampling / createSample but
    declared_capabilities.sampling is false or absent. Sampling lets
    the server invoke the client's model — undeclared use bypasses the
    client's sampling gate entirely.
  - >
    Source contains tools/call / handleToolCall / registerTool but
    declared_capabilities.tools is false. The server executes tools
    without declaring the tool capability — every I1/I2 annotation
    check is downstream of this bypass.
  - >
    resources/read handler exists but capabilities.resources is absent.
    The server serves resources the client never approved in init;
    I3/I4/I5 all assume the capability was properly declared.
  - >
    prompts/get handler exists but capabilities.prompts is absent.
    Prompt-template exposure without capability declaration.
  - >
    Multiple undeclared capabilities on the same server. The charter
    emits one finding per undeclared capability.

edge_case_strategies:
  - capability-declared-check
  - handler-vocabulary-match
  - mcp-capability-catalogue
  - per-capability-finding

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - undeclared_capability
    - charter_confidence_cap
  location_kinds:
    - capability
    - source

obsolescence:
  retire_when: >
    MCP clients enforce per-request capability checks at the wire
    layer — if a server issues a sampling/create without having
    declared sampling at init, the client rejects before the server
    handler ever runs.
---

# I12 — Capability Escalation Post-Init

Servers must DECLARE the capabilities they use at initialize time.
A server whose source contains handlers for a capability not in its
declared_capabilities escalates silently past the client's
capability gate. I12 emits one finding per undeclared capability
whose handler vocabulary is present in source.

Uses the shared `MCP_CAPABILITIES` catalogue for the handler-token
vocabulary. Confidence cap **0.88** — structural signal on source +
init metadata.
