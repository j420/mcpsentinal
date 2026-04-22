---
rule_id: A2
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: OWASP-MCP06
    url: https://owasp.org/www-project-mcp-top-10/
    summary: >
      OWASP MCP Top 10 — MCP06 Excessive Permissions. A tool description that
      claims "full access" or "unrestricted control" primes the AI to grant the
      tool the broadest possible scope without friction. Users who auto-approve
      based on metadata see the claim and skip least-privilege review.
  - kind: spec
    id: EU-AI-Act-Art-13
    url: https://eur-lex.europa.eu/eli/reg/2024/1689/oj
    summary: >
      EU AI Act Article 13 — Transparency. A description that advertises
      excessive scope without technical justification is a transparency
      violation: the stated capability does not match the minimum-necessary
      scope principle the regulation expects of high-risk AI systems.
  - kind: paper
    id: INVARIANT-LABS-MCP-INDIRECT-2025
    url: https://invariantlabs.ai/research/mcp-indirect-injection
    summary: >
      Invariant Labs (2025). Observed real-world MCP servers marketing
      themselves with sweeping scope claims ("complete access to your
      filesystem", "unlimited database control") that caused auto-approve
      clients to grant blanket permissions the user never intended.
  - kind: spec
    id: ASI03-Identity-Privilege
    url: https://genai.owasp.org/
    summary: >
      OWASP Agentic Top 10 — ASI03 Identity & Privilege Abuse. Tool
      descriptions claiming admin / root / god-mode privilege are the
      canonical anti-pattern: the claim itself is the attack surface
      because it shapes the AI's mental model of acceptable privilege
      boundaries.

lethal_edge_cases:
  - >
    "Full access" + "without restriction" paired with a write-capable
    parameter — the two linguistic signals double the evidence that
    the claim is not marketing hyperbole but a real privilege grant.
    The rule must record both phrases so the auditor sees the pairing.
  - >
    "Root access" / "admin mode" in a tool nominally scoped to a
    single directory — the description advertises privilege that the
    implementation may not actually honour, but the advertising itself
    causes the AI to treat the tool as trusted for any path. The rule
    flags the claim regardless of the implementation's real scope.
  - >
    Marketing copy with "unlimited" or "unrestricted" in a genuinely
    limited tool — legitimate superlatives are rare but possible. The
    rule downgrades confidence when the tool has structured input
    constraints (enum / maxLength / pattern) contradicting the claim.

edge_case_strategies:
  - claim-vocabulary-lookup         # typed Record of claim phrases; tokenised match
  - scope-noun-co-occurrence        # "all" / "any" / "every" must co-occur with access noun
  - constraint-contradiction-softener # lower confidence when schema is explicitly narrow

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - description_scope_claim
  location_kinds:
    - tool

obsolescence:
  retire_when: >
    MCP clients refuse to auto-approve tools whose descriptions contain
    unqualified superlative claims, OR the MCP spec adds a required
    `scope` capability declaration that supersedes free-form description
    marketing.
---

# A2 — Excessive Scope Claims in Tool Description

Detects descriptions that advertise "full / unrestricted / unlimited
access", "root / admin / god privilege", or "read / write / delete
any / all / every resource". These claims shape the AI's mental model
of acceptable privilege — even when the implementation is narrower,
the advertised claim drives auto-approval decisions.

Detection is tokenised phrase matching over a typed claim catalogue.
No regex literals.

Confidence cap: 0.80. Marketing copy can use superlatives in good
faith; we preserve reviewer headroom.
