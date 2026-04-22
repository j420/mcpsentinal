---
rule_id: E4
interface_version: v2
severity: medium

threat_refs:
  - kind: paper
    id: Invariant-Labs-Consent-Fatigue-2025
    url: https://invariantlabs.ai/blog/consent-fatigue-in-mcp
    summary: >
      Invariant Labs (2025) documented a 84.2% tool-poisoning success
      rate when MCP clients run with auto-approve enabled against
      servers exposing many benign tools alongside a small number of
      dangerous ones. The mechanism: users approve the first 10 benign
      tools and then stop scrutinising; the 11th-and-later approvals
      become automatic. E4 is the static mirror of the runtime
      phenomenon — counting tools is the cheapest proxy for the attack
      surface Invariant measured.
  - kind: spec
    id: OWASP-MCP06-Excessive-Permissions
    url: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    summary: >
      OWASP MCP Top 10 MCP06 — Excessive Permissions. A server
      exposing many tools aggregates permissions that should be split
      across focused servers. MCP06 explicitly calls this out.
  - kind: spec
    id: OWASP-ASI02-Tool-Misuse
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: >
      OWASP Agentic Security Initiative ASI02 — Tool Misuse. A server
      with >50 tools increases the probability of at least one tool
      being misused by the agent under ambiguous prompts — a classic
      ASI02 scenario.
  - kind: spec
    id: EU-AI-Act-Art-14-Human-Oversight
    url: https://eur-lex.europa.eu/eli/reg/2024/1689/oj
    summary: >
      EU AI Act Article 14 — Human Oversight. High-risk AI systems
      must enable effective human oversight. Consent fatigue from
      excessive tool counts undermines the oversight function the
      regulation requires.

lethal_edge_cases:
  - >
    Legitimately tool-rich servers (CAD, video editing, vscode-ish
    filesystem servers). Some domains genuinely need >50 tools. The
    rule is a SIGNAL; the evidence chain explicitly states the count
    and leaves the legitimate-rich determination to the reviewer.
    Remediation suggests splitting, not removing.
  - >
    Tool count just above threshold. 51 tools is not materially
    different from 50. Rule fires at strict >50; the confidence
    profile rises as count grows.
  - >
    Consent-fatigue overlap with I16. I16 (Consent Fatigue Exploitation)
    is a more targeted signal — many benign tools hiding a few
    dangerous ones. E4 is broader — ANY large tool count, regardless
    of the dangerous-tool composition. Both can fire on the same
    server (I16 would produce a higher-severity finding; E4 is the
    baseline tripwire).
  - >
    49 legitimate tools + 2 dangerous. This is I16 territory rather
    than E4. E4 does not fire when count ≤50; the reviewer must
    cross-check I16 in those cases.
  - >
    context.tools unavailable (scanner failed to enumerate). The rule
    requires context.tools. If empty, E4 does NOT fire — zero tools
    is obviously not excessive.

edge_case_strategies:
  - threshold-50-passthrough
  - tiered-factor-weight
  - cross-ref-i16

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - tool_count_over_threshold
  location_kinds:
    - capability

obsolescence:
  retire_when: >
    MCP clients default to batched-consent UX that does not induce
    consent fatigue (per-scan consent instead of per-tool), AND
    servers declare granular permission scopes per tool so oversight
    scales with tool count rather than degrades. Under those conditions
    count-based tripwires no longer correlate with oversight failure.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# E4 — Excessive Tool Count

**Author:** Senior MCP Supply-Chain Researcher + Senior MCP Security Engineer.
**Applies to:** Any MCP server with `context.tools.length > 50`.

## Relationship to I16 (Consent Fatigue Exploitation)

E4 is the broad tripwire — "too many tools, investigate". I16 is the
targeted version — "many benign + few dangerous tools, likely poisoning".
They commonly co-fire; I16 carries higher severity because the attack
shape is more specific.

## Confidence cap: 0.65

Low-medium. Tool count is a policy-dependent signal. Some domains
legitimately require 100+ tools; some should be capped at 10.
