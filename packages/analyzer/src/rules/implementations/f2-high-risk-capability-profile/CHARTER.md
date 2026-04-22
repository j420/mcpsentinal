---
rule_id: F2
interface_version: v2
severity: medium

threat_refs:
  - kind: spec
    id: OWASP-MCP-Top-10-MCP06
    url: https://genai.owasp.org/llm-mcp-top-10/
    summary: >
      OWASP MCP Top 10 MCP06 "Excessive Permissions" covers the class of
      servers whose aggregate capability surface gives an agent more
      authority than any individual tool justifies. F2 is the structural
      detector for one shape of MCP06 — a high-risk capability profile —
      detected during F1's capability-graph analysis pass and emitted as
      a companion finding. Documented in agent_docs/detection-rules.md
      §"Companion Rule Pattern".
  - kind: spec
    id: OWASP-Agentic-ASI02
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: >
      OWASP Agentic Top 10 ASI02 "Tool Misuse" names the aggregate-
      capability risk class F2 reports. The agent's own reasoning
      becomes the attack surface when unrestricted code-execution and
      network-send coexist in a single server.
  - kind: paper
    id: MCP-Sentinel-Companion-Pattern
    url: https://github.com/j420/mcpsentinal/blob/main/agent_docs/detection-rules.md
    summary: >
      MCP Sentinel's agent_docs/detection-rules.md documents the
      stub-registered companion-rule pattern. F2 is registered as a
      v2 stub whose analyze() returns [] — F1's capability-graph and
      schema-inference pass is the sole producer of F2 findings, because
      both patterns live inside the same graph traversal and re-running
      the analysis for F2 in isolation would duplicate work without
      adding signal.

lethal_edge_cases:
  - >
    Command-injection chain across two tools — untrusted-content
    ingestion tool feeds a command-execution tool via the capability
    graph. F2 companion treats this as its signature. Detected by F1
    parent's capability-graph pass; any independent analyze() on F2
    would need to rebuild the graph, which is what the companion
    pattern exists to avoid.
  - >
    Unrestricted code/command parameter on a single tool — schema
    analysis detects a `command` / `script` / `shell` / `code`
    parameter with no enum / pattern / maxLength constraint. Detected
    by F1 parent's schema-structural inference pass (the
    `unrestricted_access` cross-tool pattern).
  - >
    Executes-code + sends-network on the same tool — the classic
    "tool that can run code AND phone home" shape that MCP06
    specifically highlights. Captured inside F1 parent's graph
    pattern detector as either a command-injection chain or a
    direct lethal trifecta component depending on how the tool
    shows up alongside an untrusted-content leg.
  - >
    Multiple independent code-execution nodes inside the same server
    — N tools, each individually flagged as executes-code, together
    multiplying the agent's command surface. F1 parent aggregates
    these into one F2 emission rather than producing N separate
    findings, so the reviewer gets one auditable companion entry
    rather than a flood.
  - >
    Stub-rule silence — if the parent rule (F1) does not emit, F2
    must also not emit. The companion contract is strict: F2 findings
    exist ONLY as by-products of F1's analysis. A standalone F2
    finding with no F1 companion context would break the charter
    traceability guarantee.

edge_case_strategies:
  - companion-stub-returns-empty
  - parent-rule-is-sole-producer
  - no-duplicate-graph-traversal

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: false
  required_factors:
    - companion_of_F1

obsolescence:
  retire_when: >
    F2's companion pattern is replaced by a first-class independent
    detector — either because OWASP MCP06 narrows its scope such that
    F2 no longer matches any pattern F1 detects, OR because the F1
    graph traversal is split so that F2 can efficiently run on its
    own without duplicating the capability-graph build.
---

# F2 — High-Risk Capability Profile (Companion of F1)

**Author:** Senior MCP Threat Researcher persona.
**Status:** v2 stub. F1 is the canonical producer of F2 findings. This
rule class exists so the engine's rule dispatcher does not warn about a
missing TypedRule implementation for the string `"F2"`.

## Why this is a stub

F2 findings are emitted by F1's `analyze()` as a by-product of the same
capability-graph and schema-inference pass that detects the lethal
trifecta. Two concrete sub-patterns drive F2:

1. The graph detects a `command_injection_chain` pattern — untrusted
   content reaching an executes-code node.
2. Schema structural analysis detects an `unrestricted_access` cross-
   tool pattern — a code/command parameter without constraints.

Running F2 as a standalone rule would require rebuilding the entire
capability graph and schema analysis, then filtering for exactly these
two sub-patterns. That is wasted work — the parent rule already
produces both findings with full evidence chains.

The engine guards against silent dispatch by requiring every rule id
to have a registered TypedRule implementation; the stub satisfies that
guard while routing all real analysis through F1.

## What F2 findings look like (when emitted by F1)

- `rule_id: "F2"` (preserved across the companion emission so scorer
  and registry match YAML metadata)
- `severity: "critical"` (the companion's own severity — higher than
  F2's YAML `medium` because the specific conditions F1 detects are
  critical in practice, per the parent rule's companionMeta table)
- `owasp_category: "MCP03-command-injection"` — parent-rule attribution
- evidence chain authored inside F1's `buildCompanionFinding()`

## Why not move F2 out of the companion pattern?

The capability-graph and schema-inference analyzers are O(N²) in the
number of tools (edges between every pair). Running them twice — once
for F1, once for F2 — would double the analyzer cost with no change in
output. The companion-rule pattern is therefore a deliberate
engineering decision, not a stopgap. Documented in
agent_docs/detection-rules.md §"Companion Rule Pattern".
