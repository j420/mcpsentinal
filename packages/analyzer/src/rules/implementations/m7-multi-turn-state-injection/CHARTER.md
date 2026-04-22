---
rule_id: M7
interface_version: "v2"
severity: high

threat_refs:
  - kind: technique
    id: MITRE-ATLAS-AML.T0058
    url: https://atlas.mitre.org/techniques/AML.T0058
    summary: AML.T0058 AI Agent Context Poisoning. Tool code modifying conversation state corrupts future turns.

lethal_edge_cases:
  - Aliased mutation — const h = chat.history; h.push(msg). Rule must also flag aliased mutation one hop out.
  - Direct assignment — context.messages = [...]. Assignment is functionally identical to mutation.
  - Optional chaining — history?.push(...). Must detect optional-chain call expressions too.
  - Compiler-inserted .push — Array.prototype.push via call(). Out of scope; acknowledged.
  - Read-only filter/map — history.filter(...). Rule must NOT flag; filter is non-mutating.

edge_case_strategies:
  - one-hop-alias-mutation
  - direct-assignment-handling
  - optional-chain-detection
  - read-only-whitelist
  - call-via-filtered

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - state_mutation
  location_kinds:
    - source

confidence_cap: 0.85
---

# M7 — Multi-Turn State Injection

Tool code must not mutate conversation/history/context state. AST walker
identifies mutation method calls and direct assignments on identifiers that
match the conversation-state vocabulary. Zero regex.
