---
rule_id: I8
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: MCP-Sampling-2025-03-26
    url: https://modelcontextprotocol.io/specification/2025-03-26/server/sampling
    summary: >
      MCP 2025-03-26 sampling specification. The spec describes sampling
      as a server-to-client inference primitive but does NOT mandate
      cost controls — each sampling request triggers a paid AI
      inference on the client. Without server-side bounds, a server
      can exhaust the client's inference budget.
  - kind: paper
    id: arXiv-2601.17549-SamplingAbuse
    url: https://arxiv.org/abs/2601.17549
    summary: >
      Same paper as I7. Besides injection amplification, the work
      flags resource-exhaustion as an orthogonal attack class against
      the sampling capability — a server that issues uncontrolled
      sampling requests constitutes a financial denial-of-service
      primitive against the client operator.

lethal_edge_cases:
  - >
    Sampling declared with no visible max_tokens / maxTokens / token_limit
    / cost_limit / rate_limit / budget tokens in the server source.
    Each sampling call runs a paid inference; unbounded loops exhaust
    the client's API budget.
  - >
    Sampling handler wraps a retry loop without a backoff. Transient
    failures blow up into an exponential-cost DoS.
  - >
    Sampling called inside a tool loop over external input (e.g.
    "for each email, sample a reply"). Attacker sends 10,000 emails;
    10,000 sampling calls.
  - >
    Configuration-driven max_tokens where the config value is taken
    from a tool parameter — attacker sets max_tokens = 100k on every
    call.
  - >
    Server declares sampling but has no source code in scope — the
    charter downgrades to informational because the rule cannot
    positively verify absence of controls.

edge_case_strategies:
  - sampling-declared-check
  - cost-token-vocabulary-scan
  - source-required-else-informational
  - tool-parameter-sourced-limit-flag

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - sampling_declared
    - cost_control_absent
    - charter_confidence_cap
  location_kinds:
    - capability
    - source

obsolescence:
  retire_when: >
    MCP clients enforce a client-side rate limit + per-invocation
    token cap on sampling requests, making server-side cost controls
    an over-engineering concern rather than a prerequisite.

mutations_survived: []
mutations_acknowledged_blind: []
---

# I8 — Sampling Cost Attack

Each MCP sampling request triggers a paid AI inference on the
client. Without server-side max-token / rate-limit / budget
controls, a server — whether malicious or merely buggy — can
exhaust the client operator's inference budget. I8 detects this
as a structural signal: sampling declared, no cost-control
vocabulary visible in source.

Confidence cap **0.75** — "absence of controls" is a negative-
signal inference. Source code scope is limited; a server may
have controls the scanner cannot see. The cap is honest.
