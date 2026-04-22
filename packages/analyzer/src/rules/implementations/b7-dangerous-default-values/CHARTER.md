---
rule_id: B7
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: OWASP-MCP06
    url: https://owasp.org/www-project-mcp-top-10/
    summary: >
      OWASP MCP Top 10 — MCP06 Excessive Permissions. Schemas that default
      security-relevant parameters to permissive values (overwrite=true,
      recursive=true, disable_ssl_verify=true, read_only=false) violate
      least-privilege: callers that omit the field inherit the dangerous
      behaviour without ever making an explicit choice.
  - kind: spec
    id: OWASP-MCP07
    url: https://owasp.org/www-project-mcp-top-10/
    summary: >
      OWASP MCP Top 10 — MCP07 Insecure Configuration. Dangerous defaults
      are the canonical "configuration by omission" failure — the most
      common callers never review the value they inherited.
  - kind: paper
    id: CYBERARK-FSP-2025
    url: https://www.cyberark.com/resources/threat-research-blog/full-schema-poisoning
    summary: >
      CyberArk Labs (2025) "Full Schema Poisoning". The `default` field in
      JSON Schema is processed by LLMs as runtime-selectable state; a
      dangerous default skews the AI's first-attempt parameter value
      toward the insecure choice.

lethal_edge_cases:
  - >
    `overwrite` parameter defaults to true — callers that omit `overwrite`
    in their call silently wipe existing data.
  - >
    `recursive` parameter defaults to true on a delete / list tool —
    a single omitted field expands the blast radius to the entire
    subtree.
  - >
    `disable_ssl_verify` / `insecure` defaulting to true — SSL validation
    is silently skipped for every caller that doesn't explicitly opt out.
  - >
    `path` parameter defaults to `/` or `*` — the tool's first-call
    scope is the filesystem root or every resource.

edge_case_strategies:
  - destructive-bool-defaults
  - root-path-defaults
  - wildcard-defaults

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - dangerous_default_value
  location_kinds:
    - parameter

obsolescence:
  retire_when: >
    MCP spec mandates that all destructive flags default to false and all
    path / glob parameters default to narrow values.
---

# B7 — Dangerous Default Parameter Values

Walks each tool's input_schema and flags parameters with dangerous
default values: destructive booleans (overwrite/recursive/force/
disable_ssl_verify) defaulting to true, path parameters defaulting
to root `/`, and wildcard defaults.
