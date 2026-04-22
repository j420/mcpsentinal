---
rule_id: I5
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: MCP-NamespaceCollision-2025-03-26
    url: https://modelcontextprotocol.io/specification/2025-03-26
    summary: >
      MCP 2025-03-26 specifies separate endpoints for tools/call vs
      resources/read, but does not mandate that resource and tool names
      be disjoint. Name collisions are a confused-deputy primitive the
      spec does not prevent; I5 detects them structurally.
  - kind: paper
    id: Wiz-MCP-ResourceToolShadowing-2025
    url: https://www.wiz.io/blog/mcp-security-research-briefing
    summary: >
      Wiz Research's 2025 MCP briefing documented that AI clients
      process resource and tool names in the same context window;
      when names collide, the model confuses resource access with
      tool invocation. The ecosystem contains non-trivial collision
      rates in the wild.

lethal_edge_cases:
  - >
    Resource named "read_file" shadows the canonical destructive-by-
    convention-false tool name "read_file". Asked to "read the log
    file", the AI may invoke the tool (no argument sanitisation
    applied at the tool surface) when the user intended to access
    the resource (read-only by MCP spec).
  - >
    Resource named "execute" shadows the tool "execute". This is the
    severest case because the tool is destructive by convention. A
    user request "please execute the canned workflow" routes to
    either surface ambiguously; the tool path has side effects, the
    resource path does not.
  - >
    Near-collision via case or underscore variants — resource
    "read_File", "readFile", "read-file" against tool "read_file".
    The charter treats case- and separator-normalised identity as
    collision because AI tokenisers collapse these before name
    resolution.
  - >
    Resource collision with tool-name prefix — resource
    "delete_policy" vs tool "delete". Some clients use longest-match
    tool resolution; a resource whose name is a tool-name prefix
    creates ambiguity under those clients even without exact
    identity.
  - >
    Intra-server collision — the SAME server declares both a tool
    AND a resource with the same name. This is the most actionable
    finding because the server author chose the collision; external
    / cross-server collisions are harder to avoid.

edge_case_strategies:
  - case-insensitive-match
  - separator-normalised-match
  - prefix-collision-warning
  - destructive-tool-severity-bump
  - common-tool-vocabulary-crossref

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - name_collision_confirmed
    - charter_confidence_cap
  location_kinds:
    - resource
    - tool

obsolescence:
  retire_when: >
    MCP specification mandates disjoint name spaces for tools and
    resources, OR major AI clients require an explicit disambiguation
    prompt when a user request could resolve to either surface.

mutations_survived: []
mutations_acknowledged_blind: []
---

# I5 — Resource-Tool Shadowing

**Author:** Senior MCP Protocol Threat Researcher persona.
**Applies to:** MCP servers that declare both tools and resources.

I5 detects confused-deputy name collisions. The comparison is
case- and separator-normalised because AI tokenisers treat these
variants as equivalent when resolving tool / resource references.
A finding reports the canonical name of the catalogued common tool
it shadows (when applicable) using the shared
`COMMON_TOOL_NAMES` table — severity bumps when the collided name
is destructive-by-convention.

Confidence cap **0.80** — reflects that collision is a necessary
but not sufficient condition for exploitation; the client's tool-
resolution algorithm is the non-observable completing half.
