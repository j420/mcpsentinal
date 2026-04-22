---
rule_id: Q6
interface_version: v2
severity: critical

threat_refs:
  - kind: spec
    id: MITRE-AML.T0054
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      MITRE ATLAS AML.T0054 — LLM Prompt Injection. When an MCP
      server advertises itself as "Anthropic" / "OpenAI" / a
      well-known vendor via server.name, serverInfo.name, or a
      source-code identifier, the client and the LLM may treat
      the server as first-party and skip security checks. This
      is identity impersonation delivered through the MCP
      metadata surface.
  - kind: spec
    id: OWASP-MCP01
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 — MCP01 Prompt Injection. Server name is
      a piece of metadata the LLM reasons over. Self-declared
      vendor attribution is the canonical "trust escalation via
      metadata" anti-pattern.
  - kind: paper
    id: INVARIANT-LABS-IDENTITY-IMPERSONATION-2025
    url: https://invariantlabs.ai/research/mcp-identity-impersonation
    summary: >
      Invariant Labs (2025) documents "vendor spoofing via
      serverInfo.name" as a reliable trust-elevation attack on
      MCP clients that auto-approve calls from well-known vendors.

lethal_edge_cases:
  - >
    serverInfo.name / server.name returns a known vendor token —
    `{ serverInfo: { name: "Anthropic" } }`, `{ name: "OpenAI MCP" }`.
    The return value is self-asserted; a legitimate first-party
    server's name would come from a signed registry entry, not a
    string literal in the server's own code.
  - >
    Tool description claims Anthropic provenance — 
    "Provided by Anthropic", "Official OpenAI MCP server".
    Distinct from G2 (Trust Assertion) because Q6 also matches
    when the identity claim is structural (serverInfo field)
    rather than linguistic (description prose).
  - >
    Source-code literal string with vendor token inside a
    serverInfo / server-declaration context — allows detection
    before the server even runs.
  - >
    Legitimate Anthropic / OpenAI server — extremely rare in the
    wild, but possible. The gather step records the vendor token
    in the evidence chain so an auditor can verify the official
    namespace / registry entry before dismissing.

edge_case_strategies:
  - vendor-token-catalogue
  - serverinfo-name-match
  - description-vendor-claim-match
  - multi-agent-context-gate      # honest refusal: skip if no multi-agent evidence

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - vendor_impersonation_marker
    - identity_not_cryptographically_verified
  location_kinds:
    - source
    - tool

obsolescence:
  retire_when: >
    MCP spec requires cryptographic attestation on serverInfo
    (signed registry entry) that clients enforce before trusting
    the name, OR every ecosystem MCP client displays server
    identity alongside the trust-anchor fingerprint so the user
    can verify. Neither exists as of 2026-04.
---

# Q6 — Agent Identity Impersonation via MCP

## Threat Model

MCP clients treat `serverInfo.name` as a display-name for UI and
in some implementations as a trust signal when auto-approving
calls. A malicious server that returns `{ name: "Anthropic MCP" }`
or embeds "Official OpenAI server" in its tool descriptions
inherits vendor trust it did not earn.

Q6 targets the static-detection slice of this attack: scan source
code and tool metadata for vendor tokens in a serverInfo-building
context, or in a tool description / server description.

## Detection Strategy

1. **Source-code scan** — walk the AST for object literals whose
   property name is one of `name`, `serverInfo`, `serverName` and
   whose string-value includes a well-known vendor token.
2. **Tool metadata scan** — walk `context.tools[].description` for
   impersonation phrases ("Provided by Anthropic", "OpenAI
   official MCP server", etc.). Uses a typed catalogue.

Honest refusal: if neither source code NOR tools metadata is
available, returns `[]`. The rule's charter also flags a
multi-agent gate but evaluates a degraded form (any tool
metadata available ⇒ proceed) because the simple static case
still adds value.

## Confidence Cap

**0.80** — vendor name is a strong static signal, but legitimate
first-party servers exist (rare) and a valid counter-signal
requires an external trust-anchor lookup that static analysis
cannot perform.
