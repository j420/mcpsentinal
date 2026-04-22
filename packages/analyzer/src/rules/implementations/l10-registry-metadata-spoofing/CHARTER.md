---
rule_id: L10
interface_version: "v2"
severity: high

threat_refs:
  - kind: spec
    id: CoSAI-MCP-T6
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: CoSAI MCP-T6 — supply-chain integrity. Metadata must reflect authorship accurately.
  - kind: technique
    id: MITRE-ATLAS-AML.T0017
    url: https://atlas.mitre.org/techniques/AML.T0017
    summary: AML.T0017 — supply chain compromise via metadata impersonation.

lethal_edge_cases:
  - Author field as structured object {name, email, url} — rule must read .name not .toString().
  - Lowercase vendor substring inside legitimate-package-name — must anchor on whole-word match.
  - Multi-field carrying vendor name (author AND publisher) — one finding per field, not one per occurrence.
  - Scoped-package name prefix "@anthropic/" IS a legitimate vendor attestation — rule must NOT flag scoped packages matching the vendor prefix.
  - Vendor name appearing inside capability description rather than author field — out of scope.

edge_case_strategies:
  - structured-author-object
  - whole-word-vendor-match
  - per-field-finding
  - scoped-package-whitelist
  - author-field-only

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - vendor_in_author_field
  location_kinds:
    - config
    - source

confidence_cap: 0.80
---

# L10 — Registry Metadata Spoofing

Detects package metadata fields (author/publisher/organization/etc.)
that name a protected vendor when the package namespace itself does
NOT attest to the vendor. JSON structural walker + AST property-
assignment walker; zero regex.
