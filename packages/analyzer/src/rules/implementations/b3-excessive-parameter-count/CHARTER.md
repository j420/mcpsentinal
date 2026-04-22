---
rule_id: B3
interface_version: v2
severity: low

threat_refs:
  - kind: spec
    id: OWASP-MCP06
    url: https://owasp.org/www-project-mcp-top-10/
    summary: >
      OWASP MCP Top 10 — MCP06 Excessive Permissions. Tools with many
      parameters are harder to review, harder to validate, and expose
      a larger attack surface. A 30-parameter tool is a red flag
      regardless of intent.
  - kind: spec
    id: OWASP-Code-Review-Guide
    url: https://owasp.org/www-project-code-review-guide/
    summary: >
      OWASP Code Review Guide §5. Functions with excessive parameter
      counts consistently correlate with latent security bugs because
      reviewers under-inspect long parameter lists.
  - kind: paper
    id: API-COMPLEXITY-MEASURE-2023
    url: https://ieeexplore.ieee.org/document/10178050
    summary: >
      2023 empirical study of 10K public APIs: endpoints with >15
      parameters carried 3.2x more CWE-20 (Improper Input Validation)
      vulnerabilities than endpoints with <10 parameters.

lethal_edge_cases:
  - >
    Tool with 20+ flat parameters, none required — users and AI both
    skim the schema. Validation coverage is statistically low.
  - >
    Tool with nested objects each containing 10 fields — the top-level
    count looks fine but the effective complexity is far higher. The
    rule intentionally counts only top-level parameters to flag the
    "50 flat flags" anti-pattern; nested complexity is out-of-scope
    for v2.
  - >
    Configuration-style tool with dozens of toggles — legitimate in
    intent, but the presence of that many flags in a single call is
    a red flag. Severity is LOW because of legitimate use cases.

edge_case_strategies:
  - count-top-level-properties
  - threshold-comparison

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - parameter_count_over_threshold
  location_kinds:
    - tool

obsolescence:
  retire_when: >
    MCP clients automatically warn users when a tool schema exceeds
    15 parameters, OR the spec mandates parameter grouping via
    nested objects.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# B3 — Excessive Parameter Count

Counts top-level properties in each tool's input_schema and flags
any tool exceeding 15. Low severity by design.
