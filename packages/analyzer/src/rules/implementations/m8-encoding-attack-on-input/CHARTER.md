---
rule_id: M8
interface_version: "2.0"
severity: high

threat_refs:
  - kind: technique
    id: MITRE-ATLAS-AML.T0054
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: AML.T0054 LLM prompt injection — encoded payloads bypass pre-decode filters.

lethal_edge_cases:
  - Buffer.from with encoding other than base64 — e.g. Buffer.from(str, "utf-8") is not a decode. Must honour the second argument.
  - Validator comes AFTER the decode — the rule looks only at the text lexically after the decode call, not the whole function.
  - Sink is a local variable — decoded value is stored, then returned later. Linear lookup must follow the assigned name.
  - No input source — the argument is a constant. Must NOT flag.
  - Validator is zod.parse / joi.validate — typed schema libraries count as mitigation.

edge_case_strategies:
  - buffer-from-encoding-arg-check
  - post-decode-lexical-search
  - alias-one-hop
  - input-source-required
  - typed-schema-mitigation

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - decode_without_validation
  location_kinds:
    - source

confidence_cap: 0.80
---

# M8 — Encoding Attack on Tool Input

Detects decode calls (decodeURIComponent, atob, Buffer.from(x,'base64'), ...)
whose argument is derived from user input AND which are NOT followed by a
validator in the enclosing function's lexical suffix. AST-based; zero regex.
