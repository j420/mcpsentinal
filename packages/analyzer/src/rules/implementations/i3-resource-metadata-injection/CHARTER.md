---
rule_id: I3
interface_version: v2
severity: critical

threat_refs:
  - kind: spec
    id: MITRE-ATLAS-AML.T0054.001
    url: https://atlas.mitre.org/techniques/AML.T0054.001
    summary: >
      Indirect Prompt Injection via content channels. I3 is the MCP-
      protocol-specific detector for injection that lands in the
      resource metadata surface — name, description, URI — which
      MCP clients process alongside tool metadata during resource
      discovery.
  - kind: paper
    id: InvariantLabs-MCP-IndirectInjection-2025
    url: https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
    summary: >
      Invariant Labs documented tool-poisoning attacks through MCP
      protocol metadata. Resources are a lower-scrutiny surface than
      tools because MCP clients typically auto-discover them; any
      injection here runs before the user has a chance to review.
  - kind: spec
    id: MCP-Resources-2025-03-26
    url: https://modelcontextprotocol.io/specification/2025-03-26/server/resources
    summary: >
      MCP 2025-03-26 resources specification. Resources carry name +
      description + URI metadata that clients render into prompts and
      context without a mandatory sanitisation step.

lethal_edge_cases:
  - >
    "ignore previous instructions" style role-override in the resource
    description — visible to the AI client when it enumerates
    resources, invisible to the human reviewer who only opens the
    server homepage. The description runs as a behavioural directive
    every time the resource list is refreshed.
  - >
    LLM delimiter tokens (<|im_start|>, <|system|>, <|endoftext|>) in
    the resource NAME field. Some clients concatenate resource names
    into a bullet list inserted verbatim into the model context;
    delimiter injection in a name field bypasses all description-level
    sanitisation because the name field is rarely scrubbed.
  - >
    Authority-assertion / capability-escalation phrasing in the URI
    path itself ("…/please-always-execute/"). URI strings flow into
    the client as-is; any MCP client that prints the URI to the model
    has a third injection surface besides name and description.
  - >
    Multi-field splitting — the attacker spreads the payload across
    name + description + URI to stay below per-field linguistic
    thresholds. The gather step concatenates all three text fields
    and re-scores against the shared INJECTION_PHRASES catalogue so
    the split payload still trips the tokenised phrase matcher.
  - >
    Base64 / hex encoded injection in the URI query string. The
    client may decode the URI for display — once decoded, the
    injected instruction lands in the model context. I3 flags
    suspicious encoding markers alongside the phrase matcher.

edge_case_strategies:
  - injection-phrase-tokenisation
  - delimiter-token-match
  - multi-field-concatenation
  - encoded-payload-flag
  - lower-scrutiny-surface-emphasis

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - injection_phrase_matched
    - charter_confidence_cap
  location_kinds:
    - resource

obsolescence:
  retire_when: >
    MCP clients sandbox resource metadata from the reasoning context
    until the user explicitly reads the resource body, AND the MCP
    spec mandates resource-metadata sanitisation at the client layer.

mutations_survived: []
mutations_acknowledged_blind: []
---

# I3 — Resource Metadata Injection

**Author:** Senior MCP Protocol Threat Researcher persona.
**Applies to:** every MCP server that declares resources.

## Why a separate rule

MCP clients typically enumerate resources on connect — before any
tool is invoked, before any user prompt is entered. Injection in the
resource metadata therefore hits the model context at the earliest
possible point and with high implicit trust. A1 / A7 / A9 scan tool
descriptions; I3 scans the RESOURCE-metadata surface (name +
description + URI) that those rules do not cover.

Detection matches token sequences against the shared
`INJECTION_PHRASES` catalogue in `_shared/protocol-shape-catalogue.ts`,
with weight-weighted aggregation. Confidence cap 0.85 reflects the
linguistic nature of the signal.
