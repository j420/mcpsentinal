---
rule_id: I7
interface_version: v2
severity: critical

threat_refs:
  - kind: paper
    id: arXiv-2601.17549-SamplingAbuse
    url: https://arxiv.org/abs/2601.17549
    summary: >
      "Sampling Capability Abuse in MCP Servers" (2025). Empirically
      demonstrated 23-41% attack amplification when sampling is
      combined with content ingestion. The sampling callback re-injects
      poisoned ingested content as AI-generated output that the server
      treats as trusted — a compounding feedback loop. I7 detects the
      structural precondition: sampling declared + at least one
      ingestion tool on the same server.
  - kind: spec
    id: MCP-Sampling-2025-03-26
    url: https://modelcontextprotocol.io/specification/2025-03-26/server/sampling
    summary: >
      MCP 2025-03-26 sampling capability specification. The capability
      allows the server to invoke the client's model for inference.
      Paired with any content-ingestion surface, this is a known
      injection amplifier.
  - kind: spec
    id: MITRE-ATLAS-AML.T0054.001
    url: https://atlas.mitre.org/techniques/AML.T0054.001
    summary: >
      Indirect Prompt Injection. I7 is the MCP-protocol-specific case
      where the injection is amplified by the sampling feedback loop.

lethal_edge_cases:
  - >
    Web-scraping tool + sampling declared. Rehberger-class indirect
    injection (G1 gateway) compounds per sampling cycle — each
    cycle reinjects attacker content as if the client had generated
    it, raising the injection's trust grade with every round.
  - >
    Email reader + sampling declared. The email body contains a
    request to "use sampling to draft the reply" — the server's
    sampling call feeds the email body back into the model, this
    time framed as AI intent, with 23-41% higher success than a
    single-pass injection (arXiv 2601.17549).
  - >
    File reader + sampling. File contents are treated as more
    authoritative than web content by some models (training-data
    bias toward documentation-shaped inputs); sampling over file
    content amplifies correspondingly.
  - >
    Issue-tracker reader + sampling. Any public comment is an
    injection surface; the sampling loop multiplies success.
  - >
    Resource-fetcher + sampling. The resources/read surface is a
    lower-scrutiny ingestion channel. Sampling over resource
    content is the least-visible version of this attack.

edge_case_strategies:
  - capability-declared-check
  - ingestion-capability-graph
  - pair-finding-emission
  - amplification-factor-cited

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - sampling_declared
    - ingestion_present
    - charter_confidence_cap
  location_kinds:
    - capability
    - tool

obsolescence:
  retire_when: >
    MCP clients enforce a per-sampling-request user confirmation,
    AND the sampling spec mandates that ingestion-tool output be
    structurally tagged so the sampling callback cannot re-inject
    it into the model context.

mutations_survived: []
mutations_acknowledged_blind: []
---

# I7 — Sampling Capability Abuse

**Author:** Senior MCP Protocol Threat Researcher persona.

Sampling is the MCP capability that lets the SERVER invoke the
CLIENT's model for inference. On its own it is a useful feature.
Combined with an ingestion tool (web / email / issue / file /
resource / chat), it becomes the canonical injection amplifier
demonstrated by arXiv 2601.17549: poisoned content flows in
through the ingestion tool, the server initiates sampling, the
sampling callback returns an "AI-generated" response that the
server treats as trusted — and the trust grade of the injection
rises with every cycle.

Detection is a pair check: sampling capability declared AND at
least one content-ingestion tool present. The ingestion classifier
lives in the shared capability-graph analyzer; I7 reuses it rather
than duplicating the ingestion detection logic.

Confidence cap **0.88** — structural pair inference, not direct
payload observation.
