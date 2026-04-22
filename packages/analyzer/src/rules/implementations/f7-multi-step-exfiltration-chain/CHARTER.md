---
rule_id: F7
interface_version: v2
severity: critical

threat_refs:
  - kind: incident
    id: EmbraceTheRed-Claude-Desktop-2024Q4
    url: https://embracethered.com/blog/posts/2024/the-dangers-of-unverifiable-tool-calls-and-mcp-servers/
    summary: >
      In late 2024 Johann Rehberger (Embrace The Red) demonstrated a
      multi-step exfiltration against Claude Desktop using an MCP server
      that exposed a web-scraping tool, a base64 encoder, and an HTTP
      poster. No single tool was obviously dangerous; the attacker
      poisoned a page fetched by the scraper with instructions telling
      the agent to read a local document, encode it, and POST it to an
      attacker-controlled endpoint. The same multi-step pattern has been
      replicated by Invariant Labs (January 2026) and was the structural
      case study in Trail of Bits' February 2026 "Trust boundaries in
      agentic AI systems" — F7 exists to detect the precondition class.
  - kind: paper
    id: InvariantLabs-MCP-Exfil-Chain-2026
    url: https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
    summary: >
      Invariant Labs' 2026 write-up on MCP tool-poisoning patterns
      dedicates a section to the read→transform→send exfiltration chain.
      They argue (and F7 agrees) that the chain is undetectable by
      per-tool audit because each tool is individually benign — only the
      graph-reachability analysis that F7 performs surfaces the
      combination as a structural risk.
  - kind: spec
    id: MITRE-ATLAS-AML.T0057
    url: https://atlas.mitre.org/techniques/AML.T0057
    summary: >
      LLM Data Leakage is the ATLAS technique that frames agent-mediated
      exfiltration. F7 is the structural detector for the MCP server
      shape that gives AML.T0057 a foothold: a path from a data-reading
      node to a network-send node through zero or more
      transformation nodes, inside a single server.
  - kind: spec
    id: OWASP-MCP-Top-10-MCP04
    url: https://genai.owasp.org/llm-mcp-top-10/
    summary: >
      MCP04 Data Exfiltration covers the general risk class; F7 is the
      multi-step shape of it. Where F1 detects all three trifecta legs,
      F7 detects the weaker but more common read→send reachability (no
      untrusted-content leg required — the AI's own prompt is the
      injection vehicle).

lethal_edge_cases:
  - >
    Chain split across three or more tools with transformation hops —
    read_file → base64_encode → http_post. The middle node looks
    innocuous ("just a utility"), but it is the laundering step that
    converts sensitive bytes into a form the AI will comfortably paste
    into a URL. F7's graph reachability MUST walk through
    transformation nodes, not require a direct read→send edge, or it
    under-reports the common case documented by Embrace The Red.
  - >
    Chain with intermediate encoder that hides the payload — base64,
    hex, gzip+base64, URL-encode, Unicode-escape. The encoder is a
    first-class node of the chain, not a footnote. F7 must classify
    encoder/compressor/encrypter capabilities explicitly so the
    evidence chain names the laundering step rather than treating the
    chain as a two-hop read→send pair.
  - >
    Exfiltration sink is a legitimate-sounding tool — email_send,
    calendar_invite, slack_post, webhook. "send_email" does not read
    "suspicious" to a reviewer; the graph reachability analysis must
    not exempt it because its name sounds friendly. Any capability tag
    that matches sends-network qualifies as the sink regardless of
    naming.
  - >
    Destination parameter embedded inside a structured argument — the
    sink tool takes a JSON object whose `url` or `endpoint` field is
    buried three levels deep, not a top-level parameter. The schema
    walker must inspect the full parameter tree, not only
    top-level properties, or a dedicated attacker can dodge the
    classifier by nesting the egress field.
  - >
    Chain centrality plateau — read_file and send_webhook both score
    high centrality but the transformation tool between them scores
    low. F7 confidence must NOT require every hop to pass a centrality
    threshold; it must require the READER and SENDER hop centralities
    to pass, because transformation hops are often peripheral utilities
    whose centrality is inherently low.

edge_case_strategies:
  - graph-reachability-through-transforms
  - encoder-node-classification
  - capability-tag-by-signal-not-by-name
  - deep-schema-walker
  - centrality-at-endpoints-only

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - chain_length
    - reader_centrality
    - sender_centrality
    - transform_step_present
  location_kinds:
    - tool
    - capability

obsolescence:
  retire_when: >
    The MCP protocol introduces per-tool data-flow labels that the
    runtime enforces (e.g. a `data_origin` tag read by one tool
    forbidding its value from being passed as an argument to a
    network-capable tool), making the read→send chain unrepresentable
    at the protocol level. Until then, F7 is the static-time
    approximation the regulator asks for.
---

# F7 — Multi-Step Exfiltration Chain

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** every MCP server the registry scans with two or more tools.
F7 targets the *combination* risk, so single-tool servers are out of scope
by construction.

## What F7 proves

F7 proves, deterministically, the existence of at least one path through
the server's capability graph from a data-reading node to a network-sending
node, with zero or more transformation hops in between. The path is
discovered by the shared `capability-graph.ts` analyzer (type-compatibility
edges + capability-chain edges, BFS path-find) and confirmed by per-node
capability classification.

The structural argument:

1. A reader node is a capability node with `reads-private-data`,
   `reads-public-data`, or `accesses-filesystem` classified at confidence
   ≥ 0.5.
2. A sender node is a capability node with `sends-network` classified at
   confidence ≥ 0.5.
3. A path of length ≥ 2 exists in the data-flow graph from the reader to
   the sender.

No prompt injection payload needs to exist for F7 to fire. The rule flags
the *precondition class*, not the in-flight attack. This is deliberate:
compliance auditors (EU AI Act Art. 15, ISO 42001 A.8.2) require static
evidence of exfiltration potential, not evidence of a specific exploit.

## What F7 is NOT

- It is not F1. F1 needs all three trifecta legs, caps the total score at
  40, and is a graver finding. F7 only needs reader + sender and does not
  cap the score — it adds severity-weighted penalty like any other
  critical finding.
- It is not G1 (indirect prompt injection). G1 detects the gateway node
  that ingests untrusted content. F7 detects the exfiltration path and
  emits regardless of whether an untrusted gateway exists (because the
  user's own prompt can also initiate the read→send pattern).
- It is not a runtime detector. F7 does not observe a real exfiltration
  event — it reports the server shape that makes one possible.

## Why confidence caps below 0.99

Capability classification is multi-signal probabilistic, graph edges are
inferred (type compatibility, not observed runtime data flow), and the
path length grows uncertainty per hop. F7 caps at 0.90 — high because the
structural argument is direct, but below 0.99 because the reader/sender
classification and the edge inference are statistical.

## Companion pattern

F7 does not emit companion rule ids. F2 / F3 / F6 are emitted by F1's
analyze() and do not belong to F7's signature. F7 emits F7 findings only;
if the same capability-graph pass yields a lethal trifecta, F1's rule
class emits F1 (plus any F2 / F3 / F6 by-products) independently.
