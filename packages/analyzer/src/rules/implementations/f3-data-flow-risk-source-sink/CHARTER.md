---
rule_id: F3
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: OWASP-MCP-Top-10-MCP04
    url: https://genai.owasp.org/llm-mcp-top-10/
    summary: >
      OWASP MCP Top 10 MCP04 "Data Exfiltration" covers the class of
      source→sink data flows that F3 reports. F3 is the structural
      detector for credential-exposure paths specifically, detected
      during F1's capability-graph analysis pass and emitted as a
      companion finding. Documented in agent_docs/detection-rules.md
      §"Companion Rule Pattern".
  - kind: spec
    id: MITRE-ATLAS-AML.T0057
    url: https://atlas.mitre.org/techniques/AML.T0057
    summary: >
      AML.T0057 LLM Data Leakage frames the exfiltration class F3
      detects. Credential parameters coexisting with network-send
      parameters in the same server is a direct precursor to
      AML.T0057 — the credentials are the payload, the sender is the
      exit, no further attacker action beyond the payload nudge is
      required.
  - kind: paper
    id: MCP-Sentinel-Companion-Pattern
    url: https://github.com/j420/mcpsentinal/blob/main/agent_docs/detection-rules.md
    summary: >
      MCP Sentinel's agent_docs/detection-rules.md documents the
      stub-registered companion-rule pattern F3 follows. F1 is the
      sole producer of F3 findings — running F3 as an independent
      detector would require rebuilding the capability graph that F1
      has already constructed.

lethal_edge_cases:
  - >
    Credential-handling tool + network-send tool in the same server —
    the classic F3 shape. F1 parent detects this via the
    capability-graph `credential_exposure` pattern (BFS path from a
    `manages-credentials` node to a `sends-network` node) AND via
    schema inference's `credential_exposure` cross-tool pattern
    (credential parameter + URL parameter in the same server).
  - >
    Credential as a structured sub-field of a larger parameter —
    e.g. `auth: { token: string }` where the outer parameter does
    not look like a credential. F1's schema-inference walks the
    schema tree and classifies deep credential leaves — F3 companion
    benefits from that walker without running its own.
  - >
    Two-hop credential laundering — credential_reader → hash_fn →
    http_post. The hash step launders the credential into a form the
    sender will carry; F1's graph-reachability analysis walks
    intermediate hops, so the companion captures the full path.
  - >
    Credential pattern in description but not parameter name —
    "pass the authentication header" appears in description text
    without a `credential` parameter name. F1's multi-signal
    classifier weighs description-pattern signals against schema
    signals before emitting; false positives from pure description
    matching are filtered at the parent level before the companion
    fires.
  - >
    Stub-rule silence — F3 must not emit independently of F1. If F1
    detects no credential-exposure pattern, F3 must also emit no
    findings. The companion contract is strict: F3 findings exist
    ONLY as by-products of F1's analysis pass.

edge_case_strategies:
  - companion-stub-returns-empty
  - parent-rule-is-sole-producer
  - credential-classification-delegated-to-F1

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: false
  required_factors:
    - companion_of_F1

obsolescence:
  retire_when: >
    The MCP protocol adds a first-class "secret" data-flow label that
    the runtime enforces (credentials cannot be passed into a tool
    whose annotations declare external egress) — at which point the
    credential-exposure pattern becomes unrepresentable at the
    protocol level and F3 retires.
---

# F3 — Data Flow Risk: Source → Sink (Companion of F1)

**Author:** Senior MCP Threat Researcher persona.
**Status:** v2 stub. F1 is the canonical producer of F3 findings.

## Why this is a stub

F3 findings are emitted by F1's `analyze()` as a by-product of the
same capability-graph and schema-inference pass that detects the
lethal trifecta. The specific F3 sub-pattern is a credential-exposure
path: a node classified `manages-credentials` reachable to a node
classified `sends-network` through zero or more intermediate hops.

Both the graph-based `credential_exposure` pattern and the schema-
inference `credential_exposure` cross-tool pattern map to F3 in F1's
companion-metadata table. Running F3 as a standalone rule would
rebuild the same graph and re-execute the same reachability search.

## What F3 findings look like (when emitted by F1)

- `rule_id: "F3"` preserved across the companion emission
- `severity: "critical"` — elevated from F3's YAML `high` because the
  parent rule's detections represent fully-realised credential
  exposure paths, not theoretical ones
- `owasp_category: "MCP04-data-exfiltration"`
- `mitre_technique: "AML.T0057"`
- evidence chain authored inside F1's `buildCompanionFinding()`

## Why not move F3 out of the companion pattern?

Same economics as F2: the capability graph is O(N²) and already
built by F1. A second pass solely for F3 would double the cost with
no change in output. See agent_docs/detection-rules.md §"Companion
Rule Pattern" for the broader rationale.
