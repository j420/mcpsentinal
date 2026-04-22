---
rule_id: I1
interface_version: v2
severity: critical

threat_refs:
  - kind: spec
    id: MCP-Spec-2025-03-26-Annotations
    url: https://modelcontextprotocol.io/specification/2025-03-26/server/tools
    summary: >
      The March 2025 MCP specification introduced tool annotations
      (readOnlyHint, destructiveHint, idempotentHint, openWorldHint) as
      behavioural hints that AI clients use to make automated approval
      decisions. The spec is explicit that annotations are advisory
      self-declarations by the server — it does NOT require clients to
      cross-check annotations against the tool schema, creating a trust
      boundary where a deceptive annotation slides past every consent
      gate that keys on it.
  - kind: paper
    id: Invariant-Labs-Annotation-Deception-2025
    url: https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
    summary: >
      Invariant Labs demonstrated that ChatGPT, Cursor, Roo Code, and
      JetBrains Copilot skip the user confirmation dialog when a tool
      declares readOnlyHint: true. Attackers ship tools whose annotations
      flatly contradict the schema — readOnlyHint: true on a tool with
      delete/drop/overwrite parameters — and the client auto-executes
      without asking. The deception bypasses the strongest trust control
      in the MCP protocol, user consent.
  - kind: spec
    id: OWASP-MCP-Top-10-MCP02
    url: https://genai.owasp.org/llm-mcp-top-10/
    summary: >
      OWASP MCP02 "Tool Poisoning" specifically calls out deceptive tool
      metadata — including annotations that misrepresent capability — as
      a top-10 class of MCP vulnerability. I1 is the deterministic
      structural detector for the annotation-versus-schema-contradiction
      shape of MCP02.

lethal_edge_cases:
  - >
    Annotation claims readOnlyHint: true but schema declares a
    parameter whose name is on a destructive-verb allowlist
    (delete, remove, drop, overwrite, truncate, destroy, purge,
    wipe, erase, reset). A simple "is the tool name destructive?"
    check misses this — the deception hides one level down, in the
    parameter schema itself. I1 must walk input_schema.properties
    and classify by parameter name, not just tool name.
  - >
    Annotation contradicts description language, not parameter
    names — the tool's schema is minimal (a single untyped `args`
    property) but the description contains "deletes the specified
    record permanently". A reviewer who reads the description sees
    the destructive intent immediately, but a schema-only check
    misses it entirely. I1 must scan the description for destructive
    verbs in a handler-neutral way, using a typed vocabulary rather
    than a regex literal.
  - >
    Schema-inference confirms destructive capability structurally —
    the parameter is `target_path` (filesystem_path semantic) with
    no enum / pattern / maxLength constraint AND the tool's
    capabilities include destructive_operation at attack_surface ≥
    0.5. This is the highest-confidence variant: structural schema
    inference agrees with the parameter name, while the annotation
    claims readOnlyHint: true. I1 must escalate confidence here,
    because both independent signals point at the same gap.
  - >
    Annotation-only signal with no destructive parameter name or
    description — the tool has readOnlyHint: true and genuinely
    read-only parameters, but destructiveHint is ALSO absent AND
    the description contains a write verb buried in a benign-
    looking clause ("returns the updated record"). This is a
    lower-confidence variant — the rule must still flag, but cap
    confidence near the charter floor (0.60) so downstream scorers
    treat it as suggestive, not conclusive.
  - >
    Pure annotation mismatch without schema or description signal —
    readOnlyHint: true AND destructiveHint: true on the same tool
    (contradiction with itself). A naïve rule that only looks at
    one annotation at a time misses the self-contradiction. I1
    must treat the simultaneous presence of both hints as its own
    deception variant and emit at confidence ≥ 0.80.

edge_case_strategies:
  - destructive-parameter-vocabulary
  - description-destructive-verb-scan
  - schema-inference-cross-check
  - self-contradicting-annotations
  - confidence-floor-on-weak-signal

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - annotation_contradiction
    - destructive_signal_source
  location_kinds:
    - tool
    - parameter
    - schema
    - capability

obsolescence:
  retire_when: >
    The MCP client specification mandates cross-checking annotations
    against the tool schema before honouring auto-approval (so a
    deceptive annotation can no longer bypass consent), OR tool
    annotations are removed from the spec in favour of a verified
    capability-declaration system.
---

# I1 — Annotation Deception

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP servers exposing tools with `annotations` metadata
(MCP spec 2025-03-26 and later).

## What an auditor accepts as evidence

1. **Annotation location** — a `tool` Location naming the tool whose
   annotation is deceptive, with the exact flag combination observed
   (readOnlyHint: true; destructiveHint: absent; both: true).
2. **Contradicting signal location** — a `parameter`, `schema`, or
   `tool` Location naming the specific parameter name, description
   phrase, or inferred capability that contradicts the annotation.
3. **Trust-boundary gap** — the sink Location is the AI client's
   auto-approval path that keys on readOnlyHint. The rule's chain
   must state, in prose, which clients are known to trust this
   annotation without cross-checking (ChatGPT, Cursor, Roo Code,
   JetBrains Copilot per Invariant Labs 2025).
4. **Mitigation state** — I1 asks whether destructiveHint: true is
   also present. If it is, the contradiction is still a finding
   (self-contradiction) but confidence is slightly higher because
   the tool author cannot claim "oversight".

## What the rule does NOT claim

- It does not claim detection of annotation omission (that is I2,
  the companion stub that I1 also emits for).
- It does not claim runtime validation that the tool actually
  performs the destructive operation — static schema/description
  evidence is the ceiling for this rule class.

## Why confidence is capped at 0.85

Annotations are structured declarations; a contradiction is a
boolean proof rather than a probabilistic inference. But the
destructive-signal source is a heuristic (parameter-name
vocabulary, description scan, schema inference), so at least one
link in the chain depends on linguistic judgement. The 0.85 cap
preserves room for the case where the heuristic fires on a
genuinely read-only tool whose parameter name happens to contain
a destructive verb ("remove_filter_from_query" — read-only
despite "remove"). Downstream scorers should treat I1 findings
as high-confidence but not infallible.
