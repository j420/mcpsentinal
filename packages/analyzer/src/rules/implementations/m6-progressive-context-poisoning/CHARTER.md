---
rule_id: M6
interface_version: v2
severity: critical
owasp: ASI06-memory-context-poisoning
mitre: AML.T0058
risk_domain: prompt-injection

threat_refs:
  - kind: spec
    id: MITRE-ATLAS-AML-T0058
    url: https://atlas.mitre.org/techniques/AML.T0058
    summary: >
      MITRE ATLAS AML.T0058 (AI Agent Context Poisoning) enumerates
      persistence techniques where the attacker plants content that the
      agent re-consumes on subsequent turns. Progressive context poisoning
      is the "enablers" subclass — the server architecture that makes
      poisoning reusable across turns, not the per-message payload. M6
      is the static detector for the ENABLERS: tools that read attacker-
      reachable content AND persist it into a store the agent will later
      re-read.
  - kind: paper
    id: Invariant-Cross-Agent-Memory-2026
    url: https://invariantlabs.ai/blog/cross-agent-memory-pollution
    summary: >
      Invariant Labs (Jan 2026) documented cross-agent memory pollution
      against shared MCP vector stores and scratchpads. The vulnerability
      class is: Tool A ingests attacker content, Tool B persists the
      ingested content (often in the same server), a later agent session
      reads the store and treats the persisted content as trusted context.
      The persisted content survives for the lifetime of the store and
      taints every future session.
  - kind: paper
    id: TrailOfBits-Trust-Boundaries-2026
    url: https://blog.trailofbits.com/2026/02/trust-boundaries-agentic-ai
    summary: >
      Trail of Bits (Feb 2026) named unbounded context accumulation as the
      top shared-state vulnerability pattern in multi-agent deployments.
      The report distinguishes "single-turn poisoning" (out of scope for
      M6 — covered by A1/G1) from "progressive poisoning" where the
      attacker's incremental nudges accumulate until they cross the
      behavioural threshold the agent defaults to refusing. M6 detects
      the architectural pattern that makes progressive poisoning possible.

lethal_edge_cases:
  - >
    Reader + persistent store in the same server. Tool A reads external
    content (web, email, issue tracker); Tool B appends the content to a
    vector store / append-only scratchpad / SQLite log that Tool C later
    reads. The attacker controls what enters the store; every subsequent
    session reads the poisoned store as trusted context. M6 fires on the
    ARCHITECTURAL shape (append / push / insert / upsert with a
    context-shaped key name) rather than any specific payload, because
    the payload is the external content the store accepts verbatim.
  - >
    Unbounded accumulation (no size cap, no TTL, no clear path). The
    server appends to a context/memory/history/conversation buffer but
    never truncates, evicts, or clears. Size grows monotonically; once
    poison is in the buffer, it stays until the store is wiped by an
    operator. Detecting the absence of `limit`, `max_size`, `truncate`,
    `clear`, `reset`, `evict`, `expire`, or `ttl` anywhere near the
    append call is the signal.
  - >
    Storing LLM-generated output back into the same store the LLM reads
    from. The model's output becomes the model's next input, which is
    the canonical feedback loop. Legitimate uses exist (conversation
    summarisation) but they are almost always accompanied by a verifier
    step (integrity check, signed summary, human-in-the-loop) that M6
    looks for. Absence of a verifier combined with the loop is the
    finding.
  - >
    Vector / embedding store that ingests raw tool response output.
    Embeddings project arbitrary text into a similarity space — once
    poisoned content is indexed, every future semantic search returns it
    when the query is near enough. This is the "silent" variant of M6
    because the poisoned content need not match any exact string; it
    just needs to land in the neighbourhood of a future query.

edge_case_strategies:
  - reader-plus-persistent-store-structural-scan
  - unbounded-accumulation-no-truncation-scan
  - llm-output-feedback-loop-scan
  - vector-store-raw-ingest-scan

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - accumulation_without_bounds
  location_kinds:
    - source
    - tool

obsolescence:
  retire_when: >
    MCP gains a spec-mandated per-resource trust label that stores
    propagate through the server's reasoning layer, AND mainstream
    agent frameworks default to discarding store contents that lack a
    valid integrity signature. At that point the architectural shape
    alone is insufficient evidence because the trust label travels with
    the data.
---

# M6 — Progressive Context Poisoning Enablers

**Author:** Senior MCP JSON-RPC / Transport Security Engineer (dual persona).
**Applies to:** MCP servers whose source code is available to the scanner.

## Threat narrative

Progressive context poisoning is the class of attack where no individual
message contains a blatant injection; instead, the attacker plants many
incremental nudges that accumulate across turns until the model crosses
a behavioural threshold. The enabler is always architectural: a store
the model reads that another tool writes without a verifier.

M6 does not look for prompt-injection payloads (A1/G1/J5 handle those).
M6 looks for the SERVER-SIDE ARCHITECTURE that makes accumulation
exploitable. The shape the scanner seeks is:

  `append | push | insert | add | upsert | save | store | persist |
   write | index` over a context-shaped identifier (`context`, `memory`,
   `history`, `conversation`, `messages`, `scratchpad`, `notes`,
   `thoughts`, `reasoning`) without a nearby bound (`limit`, `max`,
   `truncate`, `clear`, `reset`, `evict`, `expire`, `ttl`).

Detection is structural (AST-based on TypeScript source when available,
line-level fallback otherwise). The lexicon lives in
`./data/accumulation-surfaces.ts` as a typed record; there are no regex
literals. Per-entry the record also declares the bound vocabulary that
nearby-ness in lines is checked against; the absence of a nearby bound
is the specific architectural signal.

## Evidence contract details

Chain:

- **source** — the accumulation call site, `{ kind: "source", file, line }`.
- **propagation** — `variable-assignment`, same location, narrating that
  the accumulated content flows back into the agent's context.
- **sink** — `config-modification`, same location, narrating that the
  persisted store is consulted by future sessions.
- **mitigation** — `input-validation` with `present: false` when no
  bound / verifier nearby; `present: true` when a bound keyword is
  within ±6 lines.
- **impact** — `cross-agent-propagation` to scope `ai-client`, exploitability
  `moderate` (requires multi-turn access but no special privileges).

Required factor: `accumulation_without_bounds` records the distance to
the nearest bound keyword (±∞ when none present in the whole file).

## Confidence cap

Capped at **0.72**. M6 is a probabilistic inference over multi-turn
behaviour, not a proof of injection. The cap is honest.

## Honest refusal

The rule skips test files (paths containing `__test__`, `.test.`,
`.spec.`) and source files shorter than 50 lines — these classes of file
frequently have helper code that matches the accumulation shape but is
not a real enabler.

## What M6 is NOT

- Not a payload detector. A1/G1/J5 detect per-message injection content.
- Not F6 (circular data loop). F6 is the tool-level read/write-same-store
  pattern inferred from tool capabilities. M6 is the CODE-level
  accumulation-without-bounds pattern inferred from source.
- Not K1/K20. K1 detects missing logging; K20 detects insufficient audit
  context. M6 detects a different class of architectural hazard.
