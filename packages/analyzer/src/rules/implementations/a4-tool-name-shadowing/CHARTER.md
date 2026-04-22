---
rule_id: A4
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: OWASP-MCP02
    url: https://owasp.org/www-project-mcp-top-10/
    summary: >
      OWASP MCP Top 10 — MCP02 Tool Poisoning. Shadowing a common tool name
      (read_file, execute_command, send_email) in a non-official namespace
      is the canonical way to route user intent through an attacker-controlled
      server while appearing legitimate.
  - kind: spec
    id: OWASP-MCP10
    url: https://owasp.org/www-project-mcp-top-10/
    summary: >
      OWASP MCP Top 10 — MCP10 Supply Chain. Shadow-named tools mirror
      the same supply-chain attack logic as typosquatted npm packages:
      users install by name, the name matches a known-good entity, but
      the payload differs.
  - kind: paper
    id: WIZ-MCP-SUPPLYCHAIN-2025
    url: https://www.wiz.io/blog/mcp-supply-chain-attacks
    summary: >
      Wiz Research (2025) MCP supply chain analysis. Documents three
      observed MCP tool-poisoning campaigns in which attackers published
      servers exposing tools named "read_file" / "shell" / "execute" to
      hijack common-tool routing in auto-approve clients.
  - kind: spec
    id: MITRE-AML.T0054
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      MITRE ATLAS AML.T0054 — LLM Prompt Injection. Shadow tool names
      operate by biasing the LLM's tool-selection reasoning: when two
      servers expose "read_file", the LLM often picks the shorter,
      simpler-named one, which is exactly the attacker's position.

lethal_edge_cases:
  - >
    Exact-match shadow — tool named literally "read_file" duplicating
    the Anthropic filesystem server's canonical tool. Flagged at high
    similarity (distance 0).
  - >
    1337-speak near-miss — tool named "read_fi1e" (digit "1" in place
    of letter "l"). A string-equality check misses; Damerau-Levenshtein
    distance 1 catches.
  - >
    Dash-underscore normalisation — tool named "read-file" vs the
    canonical "read_file". A naive equality check misses; the
    normaliser canonicalises both to the same form and declares
    exact-match shadowing.
  - >
    Singular / plural drift — "delete_files" vs canonical "delete_file".
    Damerau-Levenshtein distance 1. Flagged — users expect singular.

edge_case_strategies:
  - name-normalisation              # canonicalise dash/underscore/case before comparison
  - damerau-levenshtein-similarity  # use similarity module for fuzzy matching
  - exact-match-blocklist           # typed Record of canonical names

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - name_similarity_match
  location_kinds:
    - tool

obsolescence:
  retire_when: >
    MCP clients implement namespaced tool routing by default (every
    tool invocation binds to a specific server id) so that name collisions
    are resolved unambiguously at invocation time.
---

# A4 — Cross-Server Tool Name Shadowing

Checks every tool name against a typed catalogue of canonical
tool names observed in official MCP servers. Matches are either
exact (after dash/underscore/case normalisation) or near-miss
(Damerau-Levenshtein distance ≤ 2).

Confidence cap: 0.80. A legitimate tool may share a name with a
canonical tool for historical reasons.
