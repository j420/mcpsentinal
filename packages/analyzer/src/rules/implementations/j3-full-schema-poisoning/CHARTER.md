---
rule_id: J3
interface_version: v2
severity: critical

threat_refs:
  - kind: paper
    id: CyberArk-FSP-2025
    url: https://www.cyberark.com/resources/threat-research-blog/full-schema-poisoning-mcp
    summary: >
      CyberArk Labs (2025) "Full Schema Poisoning": demonstrated that
      LLMs process the ENTIRE JSON Schema as reasoning context, not
      just the description field. Injection in enum values, title,
      const, and default fields has equivalent effectiveness to
      description injection and is entirely missed by scanners that
      only inspect tool.description.
  - kind: spec
    id: MITRE-ATLAS-AML.T0054
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      Prompt injection through non-description schema fields is the
      same MITRE technique as description-level injection, landing
      on a different surface.

lethal_edge_cases:
  - >
    Enum value in input_schema that contains "ignore previous" or
    an LLM delimiter. The LLM reads the enum list as authoritative
    parameter documentation; injection rides on the enum.
  - >
    title field at the schema root carrying role-override phrasing.
    JSON Schema titles are human-readable labels the LLM surfaces
    alongside the description — same attention, different field.
  - >
    const value in a parameter schema containing a shell command —
    the LLM may reason "the const is the required value" and
    propose passing it unchanged.
  - >
    default values for string parameters containing injected
    directives. Schema defaults are often absorbed into the LLM's
    mental model as "what this tool expects by default".
  - >
    Payload spread across enum + title + default in the same
    schema, each below per-field phrase thresholds. The charter
    aggregates over the stringified schema to catch the spread.

edge_case_strategies:
  - schema-stringify-scan
  - injection-phrase-token-match
  - noisy-or-aggregate
  - fence-aware-demotion
  - cross-reference-b5-b7

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - schema_injection_matched
    - charter_confidence_cap
  location_kinds:
    - schema
    - tool

obsolescence:
  retire_when: >
    MCP clients strip all non-description schema fields from the
    context passed to the model, AND CyberArk's Full Schema
    Poisoning demonstrations are no longer reproducible in any
    mainstream client.

mutations_survived: []
mutations_acknowledged_blind: []
---

# J3 — Full Schema Poisoning

Extends B5/B7 to the full JSON Schema surface per CyberArk FSP
research. Detection stringifies each tool's input_schema and
matches against the shared `INJECTION_PHRASES` catalogue.
Confidence cap **0.88** — structural scan with aggregation.
