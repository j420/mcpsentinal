---
rule_id: M5
interface_version: "v2"
severity: high

threat_refs:
  - kind: spec
    id: OWASP-MCP01
    url: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    summary: >
      Context window flooding is OWASP MCP01 (prompt injection): by
      displacing safety instructions out of the attention window, the
      flood creates the same effect as a direct injection without
      needing explicit payload text.
  - kind: spec
    id: OWASP-ASI08
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: >
      ASI08 (agentic denial of service) treats unbounded output as a
      DoS substrate: the attacker triggers an agent's tool call and
      the tool returns a data set whose token cost exceeds the model's
      budget, collapsing the remaining interaction.
  - kind: spec
    id: CoSAI-MCP-T10
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      CoSAI T10 (resource exhaustion) — context window is a finite
      shared resource across all tools invoked in an agent turn; a
      single tool promising "detailed output" can exhaust it.

lethal_edge_cases:
  - >
    Pagination co-present — description says "returns all records" but
    also mentions "limit" or "page_size". A regex that matches both
    "all" and "limit" independently produces a half-mitigated finding;
    the rule must weight the mitigation down by a concrete amount
    (multiplicative 0.4) rather than drop the finding entirely, so
    the reviewer still sees the unbounded-language risk.
  - >
    Negation without pagination — "no pagination" is TWO tokens that
    together assert unbounded output. A naive "pagination is present"
    mitigation check would mis-fire here. The rule must distinguish
    "pagination" as mitigation from "no pagination" as aggravation.
  - >
    Diagnostic-only description — "returns detailed error messages".
    The token "detailed" is a verbose-output anchor and "messages" is
    a qualifier, but error-diagnostic output is bounded by error text
    length, not by dataset size. This is acknowledged as a minor
    false-positive class that the rule does not specifically filter
    (the noisy-OR is low enough that a single signal won't fire
    without a second signal).
  - >
    Description length anomaly — the description itself is 4000 chars
    of marketing copy. This flood the context window on its own,
    regardless of output claims. The rule must count description
    length as an additional signal (weight 0.45).
  - >
    Schema carries unbounded-output flag — a parameter named
    `include_all` or `dump_all` or `no_limit` or `full_output`
    suggests the tool intentionally returns unbounded results. The
    rule must scan the input_schema (structural JSON walk) for these
    field names and add the signal.

edge_case_strategies:
  - pagination-mitigation-multiplicative
  - no-pagination-is-aggravation
  - description-length-as-signal
  - schema-field-inspection
  - multi-signal-threshold

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - noisy_or_confidence
    - pagination_mitigation
  location_kinds:
    - tool
    - parameter

confidence_cap: 0.80

obsolescence:
  retire_when: >
    Every MCP client enforces a per-tool-response token budget that
    truncates responses exceeding a hard cap (e.g. 8000 tokens) AND
    returns a continuation token, making unbounded-description
    claims inert at runtime.
---

# M5 — Context Window Flooding

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** Any tool whose description or input_schema promises
verbose, unbounded, or recursive output.

## What an auditor accepts as evidence

An M5 finding must name:

1. **Source** — the tool's description surface, with a `tool`-kind
   Location.

2. **Matched signals** — each triggered signal class (verbose-output
   promise, unbounded data return, explicit no-limit claim, recursive
   expansion, unfiltered output, total data return). The noisy-OR
   combination is reported as a confidence factor.

3. **Mitigation link** — whether pagination / limit / cursor tokens
   appear in the description OR in the input_schema. Presence reduces
   the confidence multiplicatively.

4. **Impact** — context-window denial-of-service + safety-context
   displacement. The scope is the AI client (the agent model), not
   the MCP server host.

## Why confidence is capped at 0.80

Linguistic-only rules have inherent uncertainty. Even "returns all
records" can be legitimate if the data set is bounded by construction
(e.g. a lookup against a known finite set). The cap reserves headroom
for a future Phase-2 runtime check that measures actual response
sizes across a canary test suite.

## What the rule does NOT claim

- It does not run the tool; flooding is inferred from metadata only.
- It does not handle non-English descriptions.
