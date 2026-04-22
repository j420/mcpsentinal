---
rule_id: J7
interface_version: v2
severity: critical

threat_refs:
  - kind: cve
    id: CVE-2026-22785
    url: https://nvd.nist.gov/vuln/detail/CVE-2026-22785
    summary: >
      Orval OpenAPI → MCP generator code injection via spec summary /
      description fields (CVSS 9.1). An OpenAPI spec's summary field
      was interpolated verbatim into generated MCP server source code
      via template literal, turning attacker-controlled spec bytes
      into arbitrary code execution at build time.
  - kind: cve
    id: CVE-2026-23947
    url: https://nvd.nist.gov/vuln/detail/CVE-2026-23947
    summary: >
      Companion CVE to CVE-2026-22785 — operationId field of an
      OpenAPI spec interpolated into generated MCP tool names /
      function identifiers, enabling a parallel injection vector.
  - kind: spec
    id: OWASP-MCP10-supply-chain
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP10 supply chain. OpenAPI → MCP generators are a new
      supply-chain vector — poison the spec, compromise every
      generated server.

lethal_edge_cases:
  - >
    Template literal interpolating spec.summary / spec.description /
    spec.operationId into generated code without sanitisation —
    the CVE-2026-22785 pattern.
  - >
    String concatenation `"const " + operationId + " = ..."` where
    the operationId comes from an unsanitised spec — CVE-2026-23947.
  - >
    Generator writes the spec field directly into a .js / .ts file
    using fs.writeFile without escaping — the interpolation is via
    the filesystem rather than an in-memory template.
  - >
    Spec field used to build a variable name (generated identifier)
    — injected operationId "foo; evil(); //" becomes a prefix that
    opens a new statement.
  - >
    Multi-step pipeline — spec field flows through an intermediate
    cache file before reaching the generator. Static analysis must
    follow the flow across the cache to catch the pattern.

edge_case_strategies:
  - spec-field-token-catalogue
  - interpolation-token-scan
  - template-literal-detector
  - concat-detector
  - cve-precedent-reference

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - spec_field_interpolation
    - charter_confidence_cap
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP server generators (Orval, openapi-mcp-generator, etc.)
    sanitise / AST-build every spec field before emitting code,
    AND ship regression tests for CVE-2026-22785 / 23947.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
mutations_acknowledged_blind: []
---

# J7 — OpenAPI Specification Field Injection

Detects code patterns where OpenAPI spec fields (summary,
operationId, description) are interpolated into generated MCP
server code without sanitisation. Uses the shared
`OPENAPI_RISK_FIELDS` catalogue for the field vocabulary.
Confidence cap **0.88** — structural signal backed by two real
CVEs.
