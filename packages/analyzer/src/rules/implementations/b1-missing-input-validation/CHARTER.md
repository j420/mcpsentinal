---
rule_id: B1
interface_version: v2
severity: medium

threat_refs:
  - kind: spec
    id: OWASP-MCP07
    url: https://owasp.org/www-project-mcp-top-10/
    summary: >
      OWASP MCP Top 10 — MCP07 Insecure Configuration. An input schema
      that declares a string parameter without maxLength, enum, pattern,
      or format gives the AI no structural guardrail and passes
      arbitrary content to the server. Every downstream parser (SQL,
      shell, file-system path) becomes a first-pass injection target.
  - kind: spec
    id: OWASP-API-Security
    url: https://owasp.org/API-Security/
    summary: >
      OWASP API Security Top 10 — API8 Lack of Protections from
      Automated Threats. Unconstrained input fields are the canonical
      starting point for fuzzers and abuse. JSON Schema has native
      expressive constructs (maxLength, enum, pattern, format, minimum,
      maximum) that solve this problem cheaply when used.
  - kind: spec
    id: JSON-Schema-Draft-07
    url: https://json-schema.org/draft-07/json-schema-validation.html
    summary: >
      JSON Schema Draft-07 validation vocabulary. Documents the
      expected constraint keywords (maxLength, minLength, enum, pattern,
      format) for string validation and (minimum, maximum, multipleOf)
      for numbers. MCP tools inherit JSON Schema semantics — not using
      these constructs is a deliberate choice, not a limitation.

lethal_edge_cases:
  - >
    A "path" string parameter with no maxLength — accepts paths of
    unbounded length. A single-character path (`/`) on filesystem
    tools opens the root; a 10MB path crashes the parser. Either
    outcome is an exploit.
  - >
    A "command" string parameter with no pattern — the server can
    receive any shell metacharacter (";", "|", "$(...)") that the
    downstream code may pass to exec(). The schema is the first
    line of defence and it is missing.
  - >
    A "count" number parameter with no minimum/maximum — accepts
    negative values and Number.MAX_SAFE_INTEGER; either extreme can
    crash loops or allocate memory DoS. Structural integer limits
    are trivial to add.

edge_case_strategies:
  - walk-json-schema-properties
  - detect-unconstrained-string
  - detect-unconstrained-number

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - unconstrained_parameters
  location_kinds:
    - tool

obsolescence:
  retire_when: >
    MCP clients refuse to invoke tools whose parameter definitions
    lack at least one structural constraint per parameter, OR the
    MCP spec requires parameter constraints for every string/number
    input.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# B1 — Missing Input Validation

Walks the JSON Schema properties of each tool and flags any
`string` parameter that has no maxLength, enum, pattern, or format
constraint, and any `number` parameter without minimum or maximum.
Pure structural check; no regex.

Confidence cap: 0.85.
