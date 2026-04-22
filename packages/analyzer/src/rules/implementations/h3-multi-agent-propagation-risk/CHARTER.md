---
rule_id: H3
interface_version: v2
severity: high

threat_refs:
  - kind: paper
    id: EmbraceTheRed-2025-AutoGen-Cascade
    url: https://embracethered.com/blog/posts/2025/autogen-multi-agent-cascade/
    summary: >
      Johann Rehberger (Embrace The Red, November 2025) — "Prompt
      injection cascade in multi-agent AutoGen". Demonstrates how a
      prompt injection in one agent's output propagates downstream
      through the MCP integration layer: every subsequent agent that
      consumes the injected output inherits the attacker's instruction
      set. The research identifies MCP tools that accept "agent
      output" or "pipeline result" parameters as the canonical
      propagation surface. H3's primary public reference.
  - kind: paper
    id: InvariantLabs-2026-Cross-Agent-Pollution
    url: https://invariantlabs.ai/blog/cross-agent-memory-pollution-mcp
    summary: >
      Invariant Labs (January 2026) — "Cross-agent pollution via shared
      MCP memory". Documents a secondary propagation surface: MCP
      tools that write to shared memory (vector stores, scratchpads,
      working-memory files) without trust-boundary declaration. A
      compromised upstream agent writes a poisoned memory entry; every
      downstream agent that reads that memory inherits the injection
      with persistent effect across sessions.
  - kind: paper
    id: TrailOfBits-2026-Agentic-Trust-Boundaries
    url: https://blog.trailofbits.com/2026/02/agentic-trust-boundaries/
    summary: >
      Trail of Bits (February 2026) — "Trust boundaries in agentic AI
      systems". Formalises the trust-boundary model multi-agent
      architectures need: any tool that accepts input from another
      agent OR writes to a surface another agent reads MUST declare
      the source-of-trust and the propagation policy. H3 is the
      structural detector that surfaces tools missing this declaration.
  - kind: spec
    id: OWASP-ASI07-Insecure-Inter-Agent-Comms
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: >
      OWASP Agentic Top 10 — ASI07 Insecure Inter-Agent Communications.
      Agents that accept data from other agents without sanitization
      are listed explicitly as a top-10 agentic-architecture risk.
      H3 operationalises ASI07 at the MCP-tool surface.
  - kind: spec
    id: MITRE-ATLAS-AML-T0059
    url: https://atlas.mitre.org/techniques/AML.T0059
    summary: >
      MITRE ATLAS AML.T0059 — Memory Manipulation. Multi-agent systems
      share working memory through MCP tools; tools that write to
      shared memory without sanitization enable persistent cross-
      session attack state. ATLAS T0059 is the exact technique H3
      indicates against.

lethal_edge_cases:
  - >
    Tool description mentions "agent output", "upstream agent",
    "pipeline result", "previous agent" — a clear inter-agent input
    surface. The rule must classify the tool as an agent-input sink
    when the description uses this vocabulary, regardless of the
    parameter name.
  - >
    Parameter name uses the agent-input vocabulary — `agent_output`,
    `upstream_result`, `previous_agent_response`, `chain_output`,
    `workflow_result`. The rule must inspect every parameter's name
    (and its description, if any) not just the tool description.
  - >
    Tool writes to a shared-memory surface — description or schema
    implies vector-store writes, scratchpad operations, working-
    memory-file mutation. Such tools are the CAUSE of the propagation
    surface the first two classes EXPLOIT. The rule must emit a
    separate finding class for shared-memory writers with a higher
    severity.
  - >
    Tool declares BOTH roles — accepts agent output AND writes to
    shared memory. This is the canonical propagation amplifier: the
    tool is both a read-from-other-agent sink and a write-to-other-
    agent source. The rule emits a combined finding at elevated
    confidence.
  - >
    Generic "results" parameter on a tool whose description frames
    the caller as "multi-agent" or "workflow" — the vocabulary is
    indirect but the architecture implies inter-agent flow. The rule
    captures this as a lower-confidence finding (generic-results
    variant) so the reviewer can assess the architecture.
  - >
    Tool that INTENTIONALLY declares sanitization / trust boundary
    in its description — "validates upstream agent output",
    "sanitises before accepting". The rule must read the description
    for the sanitization signal and SUPPRESS the finding when the
    signal is clear. This is the legitimate-multi-agent-tool path.

edge_case_strategies:
  - agent-input-description-classifier
  - agent-input-parameter-name-classifier
  - shared-memory-writer-classifier
  - dual-role-amplifier
  - sanitization-suppression

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - propagation_sink_class
  location_kinds:
    - tool
    - parameter
    - capability

obsolescence:
  retire_when: >
    The MCP specification mandates a `trust_source` field on every
    tool parameter + a `persistence_scope` field on every output
    declaration, AND MCP clients enforce the cross-agent sanitization
    policy at the protocol layer. Under those conditions the
    trust-boundary declaration is not optional and every tool either
    complies or is rejected by the client — H3's static gap signal
    becomes redundant.
---

# H3 — Multi-Agent Propagation Risk

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** Any MCP server whose tools have been enumerated by
the scanner. The check is entirely metadata-driven (tool description,
parameter names, parameter descriptions) and does not require source
code.

## Why H3 exists

Single-agent architectures are the original MCP threat model. As
multi-agent architectures (LangGraph, AutoGen, CrewAI, Claude multi-
agent patterns) became mainstream in 2025-2026, MCP became the
integration layer between agents. Two distinct new threat surfaces
opened:

1. **Agent-input sinks** — a tool that accepts the output of another
   agent as a parameter. If the upstream agent is compromised (via
   indirect prompt injection, tool poisoning, etc.), its malicious
   output flows through this tool into the downstream agent with
   whatever authority the downstream agent is dispatched with. Johann
   Rehberger's 2025 AutoGen cascade demonstrated this end to end.

2. **Shared-memory writers** — a tool that writes into a vector
   store, scratchpad, or working-memory file that other agents then
   read. A compromised upstream agent poisons the memory; every
   downstream agent inherits the injection with persistent effect
   across sessions. Invariant Labs documented this in January 2026.

The rule is novel in the MCP scanner space — no other tool detects
these structural gaps. It is the signature rule for MCP Sentinel's
multi-agent coverage.

## What an auditor accepts as evidence

An ASI07 auditor will not accept "tool looks agent-y". They will
accept a finding that says:

1. **Classifier proof** — the finding names which of the two surfaces
   matched (agent-input sink or shared-memory writer), at which
   location (tool-kind or parameter-kind Location), with which
   vocabulary token triggered it.

2. **Sanitization-absence proof** — the finding records whether the
   tool's description contains a sanitization signal (phrases like
   "validates upstream", "sanitises", "trust boundary"). When the
   signal is PRESENT the rule does NOT fire; when ABSENT the rule
   notes the absence as evidence.

3. **Impact statement** — concrete description: a compromised
   upstream agent's instructions flow into the downstream agent
   through this tool, inheriting the downstream agent's authority.

## Why confidence is capped at 0.75

The rule operates on linguistic signals — tool descriptions and
parameter names. Those carry inherent ambiguity:

- a tool called `analyse_results` with a `results` parameter may be
  analysing sensor readings, not agent output;
- a tool named `write_memory` may be writing to a per-agent scratch
  file, not a shared memory;
- the sanitization-absence proof is a NEGATIVE signal — absence of
  a phrase is weaker than presence of a dangerous pattern.

Capping at 0.75 preserves explicit room for these externalities.

## What the rule does NOT claim

- It does not claim the tool is exploited. It claims the trust
  boundary is unmarked — an architectural gap, not an active
  compromise.
- It does not inspect the other agents that might consume the
  tool's output or shared memory. That is cross-server analysis
  out of scope for the single-server H3 signal.
