---
rule_id: Q15
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: OWASP-MCP06
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 — MCP06 Excessive Permissions. When an MCP
      server also speaks Google's A2A protocol, trust levels from
      one side of the bridge do not map onto permissions on the
      other. The A2A agent's declared skill scope can exceed the
      MCP server's declared capabilities, producing privilege
      escalation at the protocol boundary.
  - kind: spec
    id: MITRE-AML.T0054
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      MITRE ATLAS AML.T0054 — LLM Prompt Injection. A2A Agent Card
      skill descriptions, TextPart content, and push-notification
      payloads enter the MCP tool-context surface. Any prompt
      injection carried over A2A reaches the client LLM through
      the MCP tool surface — classic T0054 via a new protocol.
  - kind: spec
    id: A2A-spec
    url: https://a2a.aaif.foundation/spec
    summary: >
      Google Agent-to-Agent (A2A) protocol. Agent Cards expose
      skill metadata; TaskResults carry TextPart / FilePart /
      DataPart content; push notifications re-enter the task
      context; agent discovery advertises agents to clients.
      None of these fields has a native MCP content policy.
  - kind: spec
    id: AAIF-Linux-Foundation
    url: https://aaif.foundation/
    summary: >
      Linux Foundation AAIF (Dec 2025) — umbrella foundation
      hosting both A2A and MCP. Interoperability is explicitly
      encouraged; servers that speak both protocols are the
      emerging norm. Q15 detects the boundary-confusion attack
      surface this interoperability created.
  - kind: paper
    id: arxiv-2602-19555-fake-agent-advertisement
    url: https://arxiv.org/abs/2602.19555
    summary: >
      arXiv 2602.19555 "Fake Agent Advertisement and Unauthorized
      Registration" (2026). Demonstrates A2A agent discovery
      accepting adversarially-advertised agents; when such agents
      are exposed via an MCP bridge, they register as MCP tools
      without cryptographic verification.

lethal_edge_cases:
  - >
    A2A Agent Card skill → MCP tool description. The server reads
    `agentCard.skills[i].description` (or `.name`) and flows it
    directly into an MCP tool's description / context surface.
    Prompt-injection payloads in A2A skill metadata reach the
    client LLM via MCP.
  - >
    A2A TaskResult parts unsanitised. `task.parts[i]` /
    `result.parts[i]` where `parts` hold TextPart / FilePart /
    DataPart content passed directly as MCP tool input. No MCP
    content policy runs on the A2A-sourced bytes.
  - >
    A2A push-notification re-entry. `pushNotification` / `onPush`
    callbacks feed A2A event payloads back into the MCP context
    without re-validation — a second injection moment that the
    original request's content check never sees.
  - >
    Unverified A2A agent discovery → MCP tool registration.
    `discoverAgents()` / `a2a://` URI results advertise skills
    that register as MCP tools. No cryptographic verification
    (arXiv 2602.19555 fake-agent-advertisement).
  - >
    Protocol-boundary capability mismatch. The A2A skill scope
    (e.g. `filesystem:write`) exceeds the MCP server's declared
    capability (e.g. `tools: {}` only). Trust in one protocol
    silently grants privilege in the other.

edge_case_strategies:
  - a2a-protocol-surface-catalogue
  - a2a-to-mcp-flow-detection
  - agent-card-skill-ingestion
  - part-based-content-policy-bypass
  - honest-refusal-no-a2a-surface

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - a2a_protocol_surface_observed
    - flow_into_mcp_context
  location_kinds:
    - source

obsolescence:
  retire_when: >
    The A2A and MCP specs publish a normative cross-protocol
    trust / permission mapping AND require cryptographic
    verification for agent discovery, OR the AAIF ships a
    reference bridge that enforces content policy on every
    part / skill / push payload crossing the boundary. Neither
    exists as of 2026-04.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# Q15 — A2A/MCP Protocol Boundary Confusion

## Threat Model

The Linux Foundation's AAIF (Dec 2025) hosts both Google's A2A
and Anthropic's MCP. Servers that speak both protocols are an
emerging norm. Q15 detects the boundary-confusion attack surface
that interoperability created:

- A2A Agent Card skill descriptions flow into MCP tool context;
  any prompt-injection payload in the A2A side reaches the MCP
  client LLM.
- A2A TaskResult parts (TextPart / FilePart / DataPart) arrive
  with no MCP content policy attached.
- A2A push notifications re-enter the MCP session without the
  original content check.
- A2A agent discovery registers agents-as-tools without
  cryptographic verification (fake-agent-advertisement,
  arXiv 2602.19555).
- A2A skill scope can exceed the MCP server's declared
  capabilities (privilege escalation at the boundary).

## Detection Strategy

The gather step walks the AST for:

1. **A2A surface observed.** Identifier / PropertyAccess / string
   literal text matching the A2A-protocol vocabulary (AgentCard,
   skills, parts, TextPart, FilePart, DataPart, pushNotification,
   discoverAgents, `a2a://`).
2. **Flow into MCP context.** The same enclosing function also
   contains an MCP-side sink (tool description / input /
   toolResult / notification / registerTool) that receives a value
   derived from an A2A-surface read.
3. **Sanitiser / content-policy adjacency.** Enclosing scope
   identifiers matching sanitize / validate / enforceContentPolicy
   demote the finding (present-mitigation factor).

## Honest-Refusal Gate

If the source contains no A2A surface at all, the rule returns
immediately. Pure-MCP servers with no A2A dependency never fire.

## Confidence Cap

**0.78** — novel cross-protocol attack class. Architectural
evidence is strong (A2A + MCP in the same enclosing scope) but
at scale the boundary has limited incident history (AAIF only
formalised Dec 2025). The cap holds reviewer headroom.
