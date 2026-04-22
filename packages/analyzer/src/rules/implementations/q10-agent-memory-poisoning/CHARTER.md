---
rule_id: Q10
interface_version: "v2"
severity: high

threat_refs:
  - kind: technique
    id: MITRE-ATLAS-AML.T0058
    url: https://atlas.mitre.org/techniques/AML.T0058
    summary: >
      MITRE ATLAS AML.T0058 (AI Agent Context Poisoning). Writing
      behavioural instructions into persistent agent memory enables
      persistent prompt injection: a single poisoned record affects
      every subsequent session.
  - kind: spec
    id: OWASP-ASI06
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: >
      ASI06 (memory and context poisoning) names agent memory as a
      cross-session attack substrate. Tools that write behavioural
      content (instructions, rules, directives) to memory are the
      primary vector; read-only/append-only/facts-only memory tools
      are materially different.

lethal_edge_cases:
  - >
    Read-only memory — description says "read-only memory access,
    returns previously stored facts". The rule must detect the
    mitigation tokens ("read-only", "facts", "immutable") and drop
    confidence significantly.
  - >
    Behavioural-vs-factual ambiguity — "stores information about the
    user" could be facts (name, preferences) or instructions ("never
    ask about X"). The rule cannot distinguish without runtime
    context; it errs on the signal present in the description and
    lets the human reviewer disambiguate.
  - >
    Tool that writes system prompt — "updates the assistant's
    personality settings based on user feedback". This is the strongest
    class of signal (weight 0.90) because it directly modifies the
    safety region of the LLM's context.
  - >
    Multi-signal threshold — a single weak signal ("remembers your
    name") should not fire. The noisy-OR across two or more matched
    classes is the expected firing condition.
  - >
    Non-English description is an acknowledged gap.

edge_case_strategies:
  - mitigation-token-detection
  - weight-assignment-by-signal-class
  - multi-signal-required
  - system-context-write-escalation
  - language-acknowledge-gap

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - noisy_or_confidence
    - mitigation_adjustment
  location_kinds:
    - tool

confidence_cap: 0.80

obsolescence:
  retire_when: >
    MCP spec adds a structured `memory_category` annotation that
    declares whether a tool writes facts, instructions, or neither,
    rendering description-level heuristics unnecessary.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# Q10 — Agent Memory Poisoning

Detects tool descriptions indicating that the tool stores behavioural
instructions (directives, rules, policies) in persistent agent memory.
Linguistic rule; cap 0.80 (uncertain whether stored content is factual
or behavioural).
