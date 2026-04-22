---
rule_id: A8
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: OWASP-MCP02
    url: https://owasp.org/www-project-mcp-top-10/
    summary: >
      OWASP MCP Top 10 — MCP02 Tool Poisoning. Description-capability
      mismatch — description claims the tool is read-only while its
      parameter list exposes destructive operations — is the deceptive-
      labelling archetype unique to AI-agent contexts.
  - kind: spec
    id: OWASP-MCP01
    url: https://owasp.org/www-project-mcp-top-10/
    summary: >
      OWASP MCP Top 10 — MCP01 Prompt Injection. A deceptive read-only
      claim paired with write parameters is prompt-injection-adjacent:
      the description shapes the AI's mental model of the tool; the
      real-world effect is an unsafe privilege grant.
  - kind: paper
    id: TRAIL-OF-BITS-TRUST-BOUNDARIES-2026
    url: https://blog.trailofbits.com/2026/02/trust-boundaries-agentic-ai/
    summary: >
      Trail of Bits (February 2026) "Trust boundaries in agentic AI
      systems" — explicitly names description-capability mismatch as a
      top-3 trust-boundary violation pattern: the AI's privilege model
      is shaped by the description, not the implementation, so the
      description IS the trust boundary.
  - kind: spec
    id: MITRE-AML.T0054
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      MITRE ATLAS AML.T0054. A description that prominently claims
      read-only / safe / non-destructive primes the model to approve
      auto-execution, effectively bypassing the confirmation gate.

lethal_edge_cases:
  - >
    "Read-only" claim paired with `delete`/`remove`/`drop` parameter —
    the claim textually contradicts the capability. The rule must
    extract parameter names regardless of case and flag the mismatch.
  - >
    "Safe" claim paired with an `overwrite: true` default — the
    description's abstract safety assurance clashes with a specific
    destructive default. Must be caught even when no explicit write
    verb appears in the parameter name (the default value carries
    the capability).
  - >
    "No side effects" claim paired with a `webhook_url` parameter —
    network-send parameters contradict the no-side-effect framing
    even though no filesystem-write occurs. Must treat network
    egress as a side-effect-class capability.

edge_case_strategies:
  - read-only-claim-catalogue       # typed Record of "read-only" / "safe" phrases
  - write-verb-parameter-catalogue  # typed Record of destructive parameter name tokens
  - network-verb-parameter-catalogue # typed Record of network-send parameter name tokens
  - default-value-destructive-check  # flag destructive defaults (overwrite: true, force: true)

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - claim_parameter_mismatch
  location_kinds:
    - tool

obsolescence:
  retire_when: >
    MCP specification adds a structured `capability_tags` field that
    makes free-text description claims about capability irrelevant to
    AI trust decisions.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# A8 — Description-Capability Mismatch

Detects tool descriptions that claim "read-only", "safe",
"non-destructive", or "no side effects" while the input schema
exposes write-capable parameters. Linguistic phrase matching on
the description + structural parameter-name / default-value
analysis on the schema.

Confidence cap: 0.80. Some tools are legitimately read-only but
happen to accept a `path` parameter that contains "delete" in a
sub-word position; the rule uses token-boundary matching to avoid
those false positives.
