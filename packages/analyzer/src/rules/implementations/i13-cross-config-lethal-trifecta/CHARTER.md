---
rule_id: I13
interface_version: v2
severity: critical

threat_refs:
  - kind: paper
    id: Willison-Lethal-Trifecta-2025
    url: https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
    summary: >
      Simon Willison's 2025 formulation of the lethal trifecta — private
      data access, untrusted content ingestion, external communication —
      as a structural risk pattern no prompt-level defence can close.
      F1 is the per-server detector; I13 is the cross-server detector
      for the exact same structural pattern distributed across multiple
      MCP servers in the same client configuration. The AI client bridges
      the gap; no individual server triggers F1, but together they form
      the trifecta.
  - kind: spec
    id: OWASP-MCP-Top-10-MCP04
    url: https://genai.owasp.org/llm-mcp-top-10/
    summary: >
      OWASP MCP04 "Data Exfiltration" explicitly names multi-server
      exfiltration chains as a critical risk — data flows from one
      server's private-data tool through the AI client to another
      server's network-egress tool. I13 is the deterministic detector
      for that cross-config composition, and like F1 it caps the score
      at 40 because no partial mitigation reduces the risk.
  - kind: spec
    id: OWASP-Agentic-ASI07
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: >
      OWASP Agentic Top 10 ASI07 "Insecure Inter-Agent Communication"
      covers the class of multi-server attacks that I13 detects. The
      AI client is the inter-agent bridge; servers that individually
      pass their own audits can compose into an exfiltration chain
      when the client routes data between them without isolation.

lethal_edge_cases:
  - >
    Trifecta split across three separate servers — Server A exposes
    read-private-data tools, Server B exposes untrusted-content
    ingestion tools, Server C exposes external-comms tools. F1 fires
    on none of the three because no single server has all three
    legs. I13 must merge the toolsets and run the capability-graph
    pattern detector on the merged graph. The finding must name
    WHICH server contributed WHICH leg so a reviewer can act on a
    specific server, not just "something somewhere".
  - >
    Two-server split where one server has two of the three legs —
    Server A has (private-data + untrusted-content), Server B has
    (external-comms). Harder to detect because F1's per-server
    pass MIGHT fire on Server A with partial confidence, but the
    cross-config composition is strictly more dangerous. I13 must
    still fire on the two-server shape and emit its own finding
    alongside whatever F1 says about Server A alone.
  - >
    Honest-refusal on single-server scope — I13 requires at least
    two distinct servers to form a cross-config finding. A context
    with only one server triggers F1's territory, not I13's. The
    rule must silently return [] in that case rather than emit a
    low-confidence finding.
  - >
    Context shape — multi-server information is NOT carried on
    the standard AnalysisContext shape. It is passed as an extra
    `multi_server_tools` field attached by the scanner when it
    knows the MCP client config contains multiple servers. I13
    must honestly refuse when that extra field is absent (the
    common case during per-server scans) rather than guess.
  - >
    Score-cap preservation — I13 findings MUST carry rule_id
    "I13" as a literal string. packages/scorer/src/scorer.ts
    tests `finding.rule_id === "F1" || finding.rule_id === "I13"`
    to apply the 40-point cap. Any refactor that mangles the rule
    id (e.g. `"I13-cross-config"`) silently breaks the cap, which
    is the rule's entire reason for existence.

edge_case_strategies:
  - merge-toolset-cross-server
  - per-server-contribution-mapping
  - honest-refusal-single-server
  - literal-rule-id-for-scorer-cap

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - distributed_trifecta
    - graph_confirmed

obsolescence:
  retire_when: >
    The MCP client specification mandates per-server trust
    boundaries that prevent the client from routing data between
    tools of different servers, OR cross-server isolation becomes
    a standard deployment pattern and the trifecta distribution
    stops being a structurally observable threat.
---

# I13 — Cross-Config Lethal Trifecta

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP client configurations containing two or more
servers, analysed together so the analyzer has visibility into the
combined capability surface.

## What an auditor accepts as evidence

1. **Per-server leg mapping** — the finding names each server and
   which of the three trifecta legs (private-data, untrusted-content,
   external-comms) it contributes. Each contribution carries a `tool`
   Location so the reviewer can audit the specific tools.
2. **Cross-tool propagation link** — the chain's propagation link
   describes how the AI client bridges servers: the client invokes
   tools from all configured servers within the same session, and
   output of one server's tool becomes input to another's with no
   trust boundary in between.
3. **Sink location** — the external-comms tool(s) in the configured
   servers, each with a `tool` Location.
4. **Mitigation state** — I13 asks whether cross-server isolation
   exists in the client configuration. Today no MCP client provides
   this; the mitigation is always absent, and the finding records
   that fact.

## What the rule does NOT claim

- It does not claim detection of the prompt-injection payload that
  weaponises the trifecta (that is G1 / A1 / J5). I13 detects the
  structural precondition.
- It does not claim detection of per-server trifecta (that is F1).
  I13 fires ONLY when the three legs are distributed across ≥2
  servers in the same config.

## Why confidence is capped at 0.90

F1's structural proof reaches 0.90 because the capability-graph
analysis is deterministic and the three legs are identified by
typed vocabulary. I13 inherits that ceiling — the merged tool set
is analysed by the same capability-graph algorithm F1 uses. The
0.05-below-ceiling gap preserves room for the case where the
scanner receives an incomplete multi-server set (e.g. one server
failed to enumerate and its tools are absent from the merged
graph), which we cannot detect statically.
