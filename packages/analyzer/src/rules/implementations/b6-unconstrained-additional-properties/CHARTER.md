---
rule_id: B6
interface_version: v2
severity: medium

threat_refs:
  - kind: spec
    id: OWASP-MCP07
    url: https://owasp.org/www-project-mcp-top-10/
    summary: >
      OWASP MCP Top 10 — MCP07 Insecure Configuration. Schemas that allow
      additional (undeclared) properties accept arbitrary keys past every
      validation rule, defeating input validation entirely. The attacker
      can smuggle state through undeclared keys the handler may still
      read.
  - kind: spec
    id: JSON-Schema-Draft-07
    url: https://json-schema.org/draft-07/json-schema-validation.html
    summary: >
      JSON Schema Draft-07. `additionalProperties: true` (the default when
      unset) means the schema accepts ANY key past the declared ones.
      Security-first schemas pin `additionalProperties: false` explicitly.
  - kind: paper
    id: CYBERARK-FSP-2025
    url: https://www.cyberark.com/resources/threat-research-blog/full-schema-poisoning
    summary: >
      CyberArk Labs (2025) "Full Schema Poisoning". Documents attacks
      that smuggle side-channel state through undeclared schema keys.
      The LLM reads the schema and may include the attacker-chosen key
      because no validation forbids it.

lethal_edge_cases:
  - >
    Schema with `additionalProperties: true` explicit — the most obvious
    case; the schema author has deliberately opted out of validation.
  - >
    Schema with `additionalProperties` absent — identical effect at
    runtime. Attacker smuggles extra keys through.
  - >
    Schema with nested object `properties` where nested level omits
    `additionalProperties: false` — out-of-scope for v2 (covered by
    future B6-deep charter expansion).

edge_case_strategies:
  - check-top-level-additional-properties-flag

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - additional_properties_not_false
  location_kinds:
    - tool

obsolescence:
  retire_when: >
    MCP spec defaults additionalProperties to false for tool input schemas.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# B6 — Schema Allows Unconstrained Additional Properties

Flags any tool whose input_schema has `additionalProperties: true` or
omits the field entirely (JSON-Schema default is `true`). Pure structural.
