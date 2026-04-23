---
rule_id: I2
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: MCP-Spec-2025-03-26-Annotations
    url: https://modelcontextprotocol.io/specification/2025-03-26/server/tools
    summary: >
      The MCP specification (2025-03-26) defines destructiveHint as the
      opt-in flag that signals a tool has irreversible side effects. The
      spec does not REQUIRE servers to declare it — absence is treated by
      every AI client as "probably safe for auto-execution". I2 flags
      tools whose capability patterns indicate destructive operation but
      whose annotations block is either missing or omits destructiveHint.
  - kind: paper
    id: Invariant-Labs-Annotation-Deception-2025
    url: https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
    summary: >
      Invariant Labs' annotation-deception research demonstrates the
      downside of annotation-based trust: a tool with destructive
      capability that OMITS destructiveHint: true slides past the same
      auto-approval gate that the deceptive-annotation attack (I1)
      exploits. I2 and I1 form a paired signal; I2 is the absence-class
      counterpart to I1's explicit-contradiction class.
  - kind: spec
    id: MCP-Sentinel-Companion-Pattern
    url: https://github.com/j420/mcpsentinal/blob/main/agent_docs/detection-rules.md
    summary: >
      agent_docs/detection-rules.md §"Companion Rule Pattern" records
      I2 as a stub companion of I1. The parent rule's annotation
      analysis pass surfaces both contradicting-annotation findings
      (I1's signature) and missing-annotation findings (I2's
      signature) in a single walk of the tool set. Running I2 as a
      standalone rule would re-walk the same tools and re-build the
      same schema-inference classifications without adding signal.

lethal_edge_cases:
  - >
    Tool with multiple destructive parameters and no annotations block
    at all — attacker omits the annotations object entirely so there
    is nothing for the AI client to read. This is the simplest shape
    of the attack; I2 must recognise absence as a positive finding,
    not silence.
  - >
    Tool has annotations but destructiveHint is explicitly set to
    false despite destructive parameters. This is effectively a
    deception, but it fits I2's "missing positive signal" frame
    rather than I1's "contradicting positive signal" frame. I2 must
    flag explicit false.
  - >
    Tool with destructiveHint: true correctly set — I2 MUST NOT
    fire. The whole point of the companion pattern is that
    destructive capability with the correct annotation is not a
    finding. Omitting this edge case would turn I2 into a false-
    positive firehose on any mutative tool.
  - >
    Companion-silence contract — I2's analyze() must return [].
    Findings are produced only by I1's analyze() when it detects
    an annotation with readOnlyHint: true claim lacking matching
    destructive confirmation. A separate I2 analyze() would
    duplicate the scan and produce conflicting findings.
  - >
    Stub registration — the engine's rule dispatcher warns when a
    rule id has no TypedRuleV2 registration. I2 must register a
    stub class (technique: "stub", returns []) so the dispatcher
    stays quiet. The charter's evidence contract still declares
    source/sink because findings bearing rule_id "I2" DO exist in
    production (emitted by I1), and the contract applies to the
    findings themselves regardless of which rule class produces
    them.

edge_case_strategies:
  - companion-stub-returns-empty
  - parent-rule-is-sole-producer
  - no-duplicate-annotation-traversal

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: false
  required_factors:
    - companion_of_I1

obsolescence:
  retire_when: >
    I2's companion pattern is replaced by a first-class independent
    detector — either because the MCP spec reverses and REQUIRES
    destructiveHint on destructive tools (making absence a spec
    violation that needs its own stand-alone scanner), OR because I1
    is split so that I2 can run on its own without re-walking the
    tool set and re-running schema inference.

mutations_survived: []
mutations_acknowledged_blind: []
---

# I2 — Missing Destructive Annotation (Companion of I1)

**Author:** Senior MCP Threat Researcher persona.
**Status:** v2 stub. I1 is the canonical producer of I2 findings. This
rule class exists so the engine's rule dispatcher does not warn about
a missing TypedRule implementation for the string `"I2"`.

## Why this is a stub

I2 findings describe tools whose destructive capability is NOT
declared via `destructiveHint: true`. That judgement requires the
same two-part analysis I1 already does:

1. Does the tool's schema / parameter names / description indicate
   destructive capability?
2. Does the annotation block honestly declare it?

I1's gather.ts answers both questions as a single pass and emits
findings under both rule ids as warranted. Running I2 as a
standalone rule would re-walk the tool set and re-run
schema-inference analysis — wasted work with no new signal.

The engine guards against silent dispatch by requiring every rule
id to have a registered TypedRuleV2 implementation. This stub
satisfies that guard while routing all real analysis through I1.

## What I2 findings look like (when emitted by I1)

- `rule_id: "I2"` (preserved so scorer and registry match YAML metadata)
- `severity: "high"`
- `owasp_category: "MCP06-excessive-permissions"`
- evidence chain authored inside I1's logic that describes the
  *absence* of destructiveHint rather than the *contradiction* of
  readOnlyHint.

## Why not move I2 out of the companion pattern?

Schema-inference analysis is O(N·P) where N is the number of tools
and P is the average parameter count. Running it twice — once for
I1, once for I2 — would double analyser cost with no change in
output. The companion pattern is therefore a deliberate engineering
decision, documented in agent_docs/detection-rules.md §"Companion
Rule Pattern".
