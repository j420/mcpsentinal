# Rule Charter: mitre-aml-t0058-context-poisoning

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** critical
**Frameworks satisfied:** MITRE ATLAS AML.T0058 (exclusively)

## Threat model

MITRE ATLAS technique AML.T0058 (AI Agent Context Poisoning) covers
attacks where an adversary places content where the agent will later
read it, poisoning the reasoning context. In an MCP server, the
canonical instance is a server that exposes both:

1. **Persistent storage tools** (memory writers, vector store inserts,
   note creators), AND
2. **Read-back tools** that the agent invokes during normal operation.

The adversary writes a poisoned record once; every subsequent agent
session reads it and is influenced. The lethal pattern is the
*read-write loop on the same data store* with no record-level
provenance/trust metadata.

## Real-world references

- **MITRE ATLAS AML.T0058** — AI Agent Context Poisoning technique.
- **Embrace The Red (2024)** — persistent memory poisoning of Claude.
- **F6 (existing MCP Sentinel rule)** — circular data loop pattern.

## Lethal edge cases

1. **Memory writer + memory reader on same backend** — F6-shaped.
2. **Vector store insert + similarity search** with no source-attribution
   metadata.
3. **Note-create + note-list** where the read-back tool returns notes
   verbatim into the agent's context.
4. **Tools that store agent output** — the agent poisons itself across
   sessions.
5. **Tools that import data from external collaborators** without
   marking it as untrusted.

## Evidence the rule must gather

- Capability graph cycles where one tool's output schema is compatible
  with another tool's input semantic.
- Data-flow edges flagged by the analyzer's `circular_data_loop`
  detection (the F6 pattern).
- Whether read-back tools return content tagged with provenance.

## Strategies

- `shadow-state`
- `cross-tool-flow`
- `trust-inversion`

## Judge contract

Confirm only when `facts.context_poisoning_loops` is non-empty AND the
verdict references a tool pair on the loop.

## Remediation

Tag every persisted record with provenance metadata (creator identity,
timestamp, trust class). Read-back tools must surface the metadata to
the model and refuse to return records lacking a trust class. Provide
a trust filter that excludes records authored by the agent itself or by
external collaborators by default.

## Traceability (machine-checked)

rule_id: mitre-aml-t0058-context-poisoning
threat_refs:
- MITRE-AML-T0058
- EMBRACE-THE-RED-MEMORY-2024
- MCP-SENTINEL-F6
strategies:
- shadow-state
- cross-tool-flow
- trust-inversion
