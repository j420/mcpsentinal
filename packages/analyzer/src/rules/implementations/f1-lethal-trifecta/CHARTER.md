---
rule_id: F1
interface_version: v2
severity: critical

threat_refs:
  - kind: paper
    id: Willison-Lethal-Trifecta-2025
    url: https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
    summary: >
      Simon Willison coined the term "lethal trifecta" in 2025 to describe the
      conjunction, in a single agent context, of (1) access to private data,
      (2) exposure to untrusted content and (3) the ability to communicate
      externally. His argument is structural: no prompt-level mitigation can
      close the gap when all three legs coexist — an attacker who poisons the
      untrusted-content leg can always redirect the private-data leg out
      through the external-communication leg. The MCP surface is the largest
      production deployment of that pattern, which is why MCP Sentinel treats
      F1 as signature-class and caps the server score at 40 on detection.
  - kind: spec
    id: OWASP-MCP-Top-10-MCP04
    url: https://genai.owasp.org/llm-mcp-top-10/
    summary: >
      MCP04 "Data Exfiltration" in the OWASP MCP Top 10 identifies the
      aggregation of data-read + network-egress capabilities within a single
      MCP server as the #1 structural risk pattern. F1 is the deterministic
      detector for that pattern — not keyword matching but capability-graph
      traversal plus JSON-Schema structural inference.
  - kind: spec
    id: OWASP-Agentic-ASI06
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: >
      OWASP Agentic Top 10 ASI06 "Memory & Context Poisoning" names the exact
      attack scenario F1 flags: a downstream tool reads private state that was
      produced, directly or indirectly, by an upstream tool that ingested
      attacker-controlled content. Without isolation the private-data leg
      cannot be defended.
  - kind: spec
    id: MITRE-ATLAS-AML.T0054
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      LLM Prompt Injection is the MITRE ATLAS technique that wires the
      untrusted-content leg into the private-data + external-comms legs. F1
      does not detect the injection payload itself (A1/G1 do) — F1 detects the
      structural precondition that makes the payload weaponisable.

lethal_edge_cases:
  - >
    Split trifecta across two tools in the same server — one tool reads
    private data AND ingests untrusted content; another tool sends to the
    network. A two-tool inventory passes many naive "one tool cannot do
    all three" checks. F1 must combine per-tool capability classification
    with cross-tool graph reachability — if any node with (reads-private +
    ingests-untrusted) can reach any node with (sends-network), the
    trifecta is complete even though no single tool carries all three
    capability tags.
  - >
    Trifecta masked by a nominally-read-only capability label — tool
    annotation declares `readOnlyHint: true` but the JSON schema exposes
    a `destination`, `webhook_url`, or `recipient` parameter. The
    annotation is metadata; the parameter shape is ground truth. F1 must
    use schema-structural inference (not annotation trust) to resolve the
    contradiction, because attackers ship tools that explicitly
    misrepresent themselves.
  - >
    Trifecta via a resource URI rather than a tool — the server declares
    an MCP resource `file:///etc/secrets` AND a tool `fetch_url(url)`.
    The resource is the private-data leg; the tool is the external-comms
    leg; the AI agent performs the chaining. Capability-graph nodes must
    include resources, not just tools, or F1 under-reports servers that
    spread the trifecta across the full protocol surface (resources +
    prompts + tools).
  - >
    Low-entropy "trifecta" from utility tools — get_time + fetch_url +
    add_numbers looks three-legged by naive inspection (one tool in each
    of clock/network/compute) but carries no private-data leg at all.
    F1 confidence must reflect the weakest link: when the reads-private
    capability is below a threshold on every candidate node, the
    trifecta MUST NOT fire. Over-firing here destroys trust in the
    score cap.
  - >
    Capability confidence plateau — a single tool emits three capability
    signals with 0.51, 0.49, 0.49 confidence for reads-private /
    ingests-untrusted / sends-network. A threshold-at-0.5 classifier
    will flip findings on and off between scans for identical tool
    metadata. F1 uses the minimum of the three MAX confidences across
    the trifecta legs as its own confidence, so small threshold
    wiggles produce confidence changes, not presence/absence flips.

edge_case_strategies:
  - multi-signal-capability-classification
  - cross-tool-graph-reachability
  - schema-structural-inference
  - confidence-min-across-legs
  - score-cap-preservation

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - private_data_leg_confidence
    - untrusted_content_leg_confidence
    - external_comms_leg_confidence
    - capability_graph_signal_count
  location_kinds:
    - tool
    - capability
    - schema

obsolescence:
  retire_when: >
    The MCP protocol introduces a mandatory capability-isolation primitive
    (for example, per-tool trust domains with enforced data-flow labels
    between legs) that makes the coexistence of read-private +
    ingest-untrusted + send-network inside a single server unrepresentable
    — at which point F1's structural argument dissolves and the rule is
    superseded by the protocol guarantee.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# F1 — Lethal Trifecta

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** every MCP server the registry scans, regardless of
transport, language, or category — the trifecta is a structural
property of the server's capability surface, not a code pattern.

## What F1 proves and does not prove

F1 does not claim the server is currently being exploited. It claims
the server presents three capability legs whose coexistence, absent
per-tool isolation, produces a data-exfiltration path an adversary can
weaponise through content they control. The proof is structural:

1. **Leg 1 — reads private data.** At least one tool or resource node
   classified `reads-private-data` with confidence ≥ 0.5, inferred from
   multiple signals: parameter semantics (credential / file-path /
   identifier), schema structure (object-returning shapes that expose
   user records), annotation cross-check, and description pattern
   clusters.
2. **Leg 2 — ingests untrusted content.** At least one node classified
   `ingests-untrusted` with confidence ≥ 0.5. Email readers, scrapers,
   issue trackers, chat ingesters, file readers from user-writable
   paths all produce this classification.
3. **Leg 3 — sends network.** At least one node classified
   `sends-network` with confidence ≥ 0.5. This is the egress — webhooks,
   HTTP clients, email senders, Slack bots.

The three legs need NOT live on one tool. F1 runs capability-graph
traversal and schema-structural inference jointly: if any path through
the data-flow graph connects a private-data source to a network sink,
AND any node on that path is classified ingests-untrusted, the
trifecta is complete.

## Why F1 caps the total score at 40

The score cap is not decorative — it is the product-level
expression of the trifecta being a *structural* risk rather than an
incremental one. A server with the trifecta and no other findings is
still materially less safe than a server with several medium-severity
findings and no trifecta, because the trifecta eliminates the client-
side defences the other findings assume (user review, per-tool
sandboxing, destination allowlists). The cap enforces that ordering in
the published score.

## Companion-rule emission (F2, F3, F6)

F1's capability-graph traversal produces more information than F1
alone consumes. By-product findings are emitted under three companion
rule ids:

- **F2** — High-Risk Capability Profile. Emitted when a
  command-injection chain is detected inside the same graph (untrusted
  content reaching executes-code) or when schema analysis identifies an
  unconstrained code/command parameter.
- **F3** — Data Flow Risk Source→Sink. Emitted when a credential-
  exposure edge is detected: credential-handling node reachable to a
  network-send node without isolation.
- **F6** — Circular Data Loop. Emitted when DFS cycle detection finds
  a (writes-data, reads-data) cycle on a shared data store — the
  persistent-prompt-injection primitive.

F2, F3, F6 each have their own `<rule>/` directory with a v2 stub
that returns `[]`; F1 is the canonical emission site for all three
rule ids. This is the documented companion-rule pattern (see
agent_docs/detection-rules.md §"Companion Rule Pattern").

## What F1 is NOT

- It is not a payload detector. A1 / G1 detect the injection content.
  F1 detects the preconditions that make any such content dangerous.
- It is not a single-tool safety check. B7 / I1 / I2 check individual
  tool declarations; F1 checks the *combinatorial* posture.
- It is not a description-keyword rule. Inputs are capability graphs
  and schema structural inference — no keyword-matching shortcuts.

## Why confidence caps below 0.99

The three-leg minimum is a hard structural signal, so F1 floors its
base confidence higher than a typical one-site rule. But capability
classification is multi-signal probabilistic: a 0.6 / 0.6 / 0.6 score
on the three legs produces real uncertainty that must be honoured. F1
takes the *minimum* of the three leg MAX confidences as its reported
confidence, then applies the mitigation/cross-tool factors on top.
When all three legs are 0.9+ with multiple corroborating signals, F1
can reach the 0.90 ceiling — not higher, because the graph is still
inferred, not observed at runtime.
