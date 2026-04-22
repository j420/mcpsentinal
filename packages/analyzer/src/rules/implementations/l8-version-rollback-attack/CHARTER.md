---
rule_id: L8
interface_version: "v2"
severity: high

threat_refs:
  - kind: spec
    id: CoSAI-MCP-T6
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: CoSAI MCP-T6 (supply chain integrity) — dependency overrides that force old versions bypass integrity.
  - kind: spec
    id: OWASP-ASI04
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: ASI04 (agentic supply chain) — version rollback re-introduces patched CVEs.
  - kind: technique
    id: MITRE-ATLAS-AML.T0017
    url: https://atlas.mitre.org/techniques/AML.T0017
    summary: AML.T0017 (supply chain compromise) — pinning to outdated versions is one path.

lethal_edge_cases:
  - Overrides section in package.json maps an MCP-critical package to "0.1.0" — must flag as CRITICAL even though syntactically valid.
  - pnpm.overrides nested object — structural JSON walk must descend into pnpm.overrides.
  - Install command in a string literal inside source code — hand-written parser (no regex) must detect `npm install pkg@0.1.0`.
  - Range constraints like "<=1.0.0" / "<1.x" — hand-written semver comparator flags open-ended lower bounds.
  - Legitimate pin to latest x.y.z — must NOT flag "^5.2.3" where the major is current.

edge_case_strategies:
  - structural-json-walk
  - install-command-token-walker
  - semver-lexical-compare
  - mcp-critical-prefix-escalation

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - old_version_confidence
    - mcp_critical_escalation
  location_kinds:
    - config
    - source

confidence_cap: 0.85
---

# L8 — Version Rollback Attack

Detects dependency override sections or install commands that pin a package
to an old/vulnerable version. MCP-critical package prefixes escalate to
CRITICAL severity.
