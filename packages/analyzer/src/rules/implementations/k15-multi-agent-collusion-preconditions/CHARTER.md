---
rule_id: K15
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: MAESTRO-L7
    url: https://cloudsecurityalliance.org/research/topics/multi-agent-threat-modeling
    summary: >
      MAESTRO Layer 7 (Agent Ecosystem) names goal-misalignment cascades
      and inter-agent collusion as the primary class of multi-agent
      threats. When one agent writes content into a surface another
      agent reads without an attested trust boundary, the servers
      involved are complicit in the collusion channel whether they
      intend it or not.
  - kind: spec
    id: CoSAI-MCP-T9
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      CoSAI MCP threat taxonomy T9 — Trust Boundary Failures between
      agents. The taxonomy is explicit that any cross-agent write/read
      surface without a trust attestation IS the boundary failure; the
      absence of a runtime attack is not a mitigation.
  - kind: spec
    id: OWASP-ASI07
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: >
      OWASP Agentic Security Initiative ASI07 — Insecure Inter-Agent
      Communication. Names "shared memory / scratchpad / vector store
      without access control" as the archetype. K15 detects the static
      precondition statically; runtime collusion detection belongs to
      a behavioural monitor.
  - kind: paper
    id: InvariantLabs-CrossAgent-Pollution-2026
    url: https://invariantlabs.ai/
    summary: >
      Invariant Labs "Cross-agent pollution via shared MCP memory"
      (Jan 2026) demonstrated a compromised upstream agent writing
      poisoned records into a shared vector store that every
      downstream agent read and acted on. K15 detects the shape
      (shared write sink + undeclared trust boundary) without
      requiring the runtime trace.
  - kind: paper
    id: EmbraceTheRed-CrossAgent-AutoGen-2025
    url: https://embracethered.com/blog/
    summary: >
      Johann Rehberger (Nov 2025) demonstrated cross-agent prompt
      injection cascades in AutoGen via shared MCP tools. K15 is the
      static detector for the shape he exploited — write-surface
      tools without trust-boundary annotation paired with read-surface
      consumers.

lethal_edge_cases:
  - >
    Write to a "session memory" tool name that is NOT in the
    canonical vocabulary — e.g. a team calls their shared store
    `workspace_note` rather than `memory` or `scratchpad`. The
    rule would miss it. The classifier uses token decomposition
    on tool names AND inspects tool descriptions for shared-state
    language (memory, shared, scratchpad, workspace, vector,
    session-state, agent-state, pool, queue).
  - >
    Single-server trifecta — the same server contains BOTH a
    write-to-shared and a read-from-shared tool. A naive rule
    that only fires when the shared-state lives on a SEPARATE
    server misses it. The rule fires whenever a pair exists in
    the same tool enumeration, because the cross-agent surface
    is the tool shape, not the server boundary.
  - >
    Trust boundary declared in a language the static analyzer does
    not read — e.g. the server's README.md says "this tool is
    isolated per agent". A text-only check of tool descriptions
    would miss the README. The rule requires a machine-readable
    declaration: tool annotation `destructiveHint: false` + an
    explicit `trustBoundary` annotation key, OR an
    `input_schema.properties.agent_id` with `required: true`, OR
    a tool-name token "isolated" / "scoped" / "private".
  - >
    False-positive on a logger — a tool called `log_message`
    writes but the content is for human operators, not for
    downstream agents. The rule's read-side classifier requires
    at least one corresponding READ tool on the same server;
    isolated write-only or read-only tools do not fire.
  - >
    Tool name contains `shared` but semantics are per-user (e.g.
    `read_shared_document` where "shared" means "shared with
    you"). The rule prioritises machine-readable signals
    (schema / annotations) over linguistic heuristics and
    down-weights linguistic-only matches in confidence scoring.

edge_case_strategies:
  - shared-state-vocabulary            # tokenised name + description for shared-surface identification
  - paired-write-read-on-same-server   # require both sides of the collusion channel
  - attestation-detection              # recognize destructiveHint false + trustBoundary annotation / agent_id / isolated-scoped
  - write-only-read-only-filter        # do not fire when only one side of the pair exists
  - linguistic-downweight              # description-only matches reduce confidence

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - shared_write_tool
    - corresponding_read_tool
    - no_trust_boundary_attestation
  location_kinds:
    - tool
    - parameter

obsolescence:
  retire_when: >
    MCP specification adds a first-class "trustBoundary" protocol
    primitive with a mandatory attestation field every tool
    writing to a multi-agent surface must set — at which point
    the static detection shifts to "is the attestation present?"
    which is a different rule.
---

# K15 — Multi-Agent Collusion Preconditions

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP servers that expose tools which write to a shared
memory / scratchpad / vector store AND tools that read from it.

## What an auditor accepts as evidence

A MAESTRO L7 auditor will not accept "this server uses shared state".
They will accept a rule that:

1. Names the specific **write-surface tool** — a concrete tool name
   with a `tool`-kind Location — and classifies its write target
   (`memory`, `scratchpad`, `vector-store`, `session-state`).

2. Names the specific **read-surface tool(s)** from the same server
   whose input schema or description claims to read the same
   surface.

3. Reports the **mitigation** check — whether a machine-readable
   trust-boundary attestation exists (tool annotation `trustBoundary`,
   a required `agent_id` parameter, or an isolation-signalling name
   token).

4. States the **impact** in concrete terms — a compromised upstream
   agent writes poisoned content, a downstream agent reads it and
   acts. The organisation cannot demonstrate "agent isolation" under
   MAESTRO L7 until the attestation becomes machine-checkable.

## Confidence cap — 0.85

Runtime collusion behaviour is invisible to static analysis.
Conversely, the MACHINE-READABLE attestation signals the rule looks
for may be absent because the feature has not yet been standardised
in the MCP protocol — not because the server is hostile. The 0.85
cap prevents overclaiming.
