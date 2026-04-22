---
rule_id: M2
interface_version: "2.0"
severity: high

threat_refs:
  - kind: technique
    id: MITRE-ATLAS-AML.T0057
    url: https://atlas.mitre.org/techniques/AML.T0057
    summary: AML.T0057 LLM data leakage — system prompts are sensitive configuration that must not leak into tool responses.

lethal_edge_cases:
  - Aliased system-prompt identifier — const sp = systemPrompt; return sp. Rule must resolve the alias one hop.
  - Redaction in a different branch — prompt is returned in one code path and redacted in another. Rule reports per-return, not per-function.
  - Spread into response object — res.json({ ...data, systemPrompt }). Must detect shorthand property in the spread.
  - Conditional redaction — if (debugMode) return systemPrompt. Rule still reports because the branch is live.
  - Template literal concatenation — "Hello " + systemPrompt + " tail". AST walker must detect identifier inside binary / template.

edge_case_strategies:
  - one-hop-alias
  - per-return-site
  - shorthand-property-detection
  - conditional-branches-reported
  - binary-and-template-detection

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - prompt_in_return_path
  location_kinds:
    - source

confidence_cap: 0.80
---

# M2 — Prompt Leaking via Tool Response

Detects system-prompt identifiers flowing into a tool response (return
statement or response sink method) without a redaction/mask/sanitize
call in the enclosing scope. AST-based; zero regex.
