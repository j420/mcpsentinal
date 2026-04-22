---
rule_id: B4
interface_version: v2
severity: medium

threat_refs:
  - kind: spec
    id: OWASP-MCP07
    url: https://owasp.org/www-project-mcp-top-10/
    summary: >
      OWASP MCP Top 10 — MCP07 Insecure Configuration. A tool without
      an input_schema provides the AI no structural contract; the AI
      fabricates parameter types and values from the description alone.
      Every invocation is a guess that bypasses every schema-level
      defence.
  - kind: spec
    id: MCP-Specification
    url: https://modelcontextprotocol.io/specification
    summary: >
      The MCP specification documents input_schema as a JSON Schema
      declaration. A tool that omits input_schema is spec-ambiguous;
      different clients interpret the absence differently (some reject
      the tool, some allow arbitrary JSON). Either outcome undermines
      predictable behaviour.
  - kind: spec
    id: JSON-Schema-Draft-07
    url: https://json-schema.org/draft-07/json-schema-validation.html
    summary: >
      JSON Schema is the industry-standard contract for validating
      structured inputs. Omitting it collapses the client-server
      contract to natural language description, which is non-
      executable and therefore unverifiable.

lethal_edge_cases:
  - >
    Tool with null input_schema — AI fabricates parameters from the
    description. Dangerous when the description implies a sensitive
    operation (delete, exec) because the AI's guess is ungoverned.
  - >
    Tool with undefined input_schema field — equivalent to null for
    scanning purposes. Must treat both the same way.
  - >
    Tool with empty object input_schema `{}` — not "absent" in
    memory but semantically equivalent. NOT covered by B4 (covered
    by B1 / B6). Charter acknowledges the split responsibility.

edge_case_strategies:
  - null-or-undefined-input-schema-check

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - no_input_schema
  location_kinds:
    - tool

obsolescence:
  retire_when: >
    MCP spec rejects tools with no input_schema at registration time.
---

# B4 — Schema-less Tools

Flags any tool whose `input_schema` field is null or undefined.
Structural check; no regex.
