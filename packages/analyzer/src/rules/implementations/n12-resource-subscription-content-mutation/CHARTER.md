---
rule_id: N12
interface_version: v2
severity: critical
owasp: MCP01-prompt-injection
mitre: AML.T0058
risk_domain: protocol-transport

threat_refs:
  - kind: spec
    id: MCP-Resources-Subscribe
    url: https://modelcontextprotocol.io/specification/2025-03-26/server/resources#subscriptions
    summary: >
      MCP `resources/subscribe` + `notifications/resources/updated` lets
      a client subscribe to a resource URI and receive server-pushed
      updates when the resource content changes. The spec does NOT
      require clients to re-verify the content integrity on every
      update — they may optimistically trust that the subscribed
      resource is still the same one they agreed to read. This is a
      time-of-check vs time-of-use (TOCTOU) surface at the protocol
      layer.
  - kind: paper
    id: Invariant-Subscription-Mutation-2026
    url: https://invariantlabs.ai/blog/resource-subscription-poisoning
    summary: >
      Invariant Labs (2026) documented resource-subscription poisoning
      attacks against MCP agentic clients. An attacker who gains the
      ability to modify the subscribed resource (e.g. a shared document,
      a database row) pushes adversary-controlled updates that the
      agent ingests with the trust it granted at subscribe time.
  - kind: spec
    id: MITRE-ATLAS-AML-T0058
    url: https://atlas.mitre.org/techniques/AML.T0058
    summary: >
      Subscription content mutation is the realisation of AML.T0058
      (AI Agent Context Poisoning) at the MCP resource surface. The
      trust boundary is established once and then silently invalidated
      by content mutation.

lethal_edge_cases:
  - >
    `notifications/resources/updated` handler that forwards the new
    content to the agent's context without re-running the integrity /
    provenance check the subscribe step did. The attacker mutates the
    resource (shared document, shared config, shared record) and the
    agent treats the mutation as the original resource.
  - >
    Subscription mutation without a signed / hashed envelope. The
    client has no way to tell that the content delivered in the
    update is different from the content it subscribed to. Integrity
    checks would catch this; the rule flags their absence.
  - >
    Resource update coalescing where the server silently drops the
    "updated" notification because a later update supersedes an
    earlier one — the agent never sees an intermediate malicious state
    but inherits its accumulated effects. Subtle; detected when the
    update handler emits without serialising an ordered versioning
    check.
  - >
    Cross-server subscription relay: one MCP server subscribes to a
    second MCP server's resource and republishes updates to its own
    agents. The relay's integrity check (if any) is the only defence;
    absence = transparent pass-through of adversary content.

edge_case_strategies:
  - subscription-update-handler-no-integrity-scan
  - resource-update-hash-absent-scan
  - coalescing-update-unchecked-scan
  - cross-server-relay-pass-through-scan

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - integrity_check_absent
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP spec mandates that subscribe + updated pair carry matched
    integrity signatures and clients verify on every update. Until
    then, server-side avoidance is primary.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# N12 — Resource Subscription Content Mutation

Honest-refusal: skips when the file does not mention
`notifications/resources/updated` or `resources/subscribe`. Uses shared
MCP method catalogue. Confidence cap 0.78.
