# Rule Charter: multi-agent-trust-boundary

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** high
**Frameworks satisfied:** OWASP ASI07, OWASP MCP04, CoSAI T9, MAESTRO L7, EU AI Act Art.14, MITRE AML.T0059

## Threat model

Multi-agent orchestration (LangGraph, AutoGen, CrewAI, Claude
multi-agent patterns) uses MCP as the integration layer between
agents. A compromised upstream agent propagates injected instructions
downstream by writing to a tool whose output is consumed by another
agent, or by writing to shared agent memory (vector stores,
scratchpads, session state) that any downstream agent reads.

The failure pattern: a server exposes both **cross-agent writers**
(tools that write to shared agent state) and **cross-agent readers**
(tools that consume another agent's output) without declaring a trust
boundary. Any compromise of one agent pollutes every downstream agent
that shares the server.

This is documented in real-world attacks: Embrace The Red (Nov 2025),
Invariant Labs (Jan 2026) "Cross-agent pollution via shared MCP memory",
Trail of Bits (Feb 2026) "Trust boundaries in agentic AI systems".

## Real-world references

- **EmbraceTheRed-2025-11** — "Prompt injection cascade in multi-agent
  AutoGen"; demonstrated cross-agent pollution via MCP.
- **InvariantLabs-2026-01** — Cross-agent memory poisoning research.
- **TrailOfBits-2026-02** — Trust boundaries in agentic AI systems.
- **OWASP-ASI07** — Insecure Inter-Agent Communication.
- **MITRE-AML.T0059** — Memory Manipulation.

## Lethal edge cases

1. **Shared vector store** — both read_memory and write_memory exist in
   the same server, no trust tagging on the read path.
2. **Scratchpad writer consumed by a downstream agent's planner** — a
   writer tool whose output flows to any downstream reader in the
   same config.
3. **Cross-agent relay via tool name shadow** — a destructive tool is
   named identically to a benign upstream tool, confusing the
   downstream orchestrator.
4. **No declared trust boundary annotation** — tool metadata carries
   no key attesting "input must be trusted" or "output is tainted".

## Evidence the rule must gather

- Capability-graph traversal: find nodes with both `writes-data` and
  `reads-private-data` (the shared-memory pattern) OR both write and
  read tools against the same resource name.
- Input-channel semantics: find tools whose input channel is
  `json_data` or `text_content` coming from another agent (heuristic
  based on parameter naming).
- Per-tool annotation scan for a trust marker via the centralized
  consent marker catalog.

## Strategies (for runtime test generation)

- `cross-tool-flow`
- `shadow-state`
- `trust-inversion`

## Judge contract

A "fail" verdict is confirmed only if `facts.untrusted_relay_tools` is
non-empty AND the LLM's `evidence_path_used` references one of those
tool names.

## Remediation

Declare trust boundaries explicitly: add a `trustBoundary` annotation
to every cross-agent relay tool, gate write operations behind
human-in-the-loop confirmation, and never expose a shared-memory
read/write pair in a single server without integrity tagging on the
stored payloads.

## Traceability (machine-checked)

rule_id: shared-multi-agent-trust-boundary
threat_refs:
- EmbraceTheRed-2025-11
- InvariantLabs-2026-01
- TrailOfBits-2026-02
- OWASP-ASI07
- MITRE-AML.T0059
strategies:
- cross-tool-flow
- shadow-state
- trust-inversion
