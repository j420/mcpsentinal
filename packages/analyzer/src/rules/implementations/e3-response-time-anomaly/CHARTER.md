---
rule_id: E3
interface_version: v2
severity: low

threat_refs:
  - kind: spec
    id: OWASP-MCP09-Logging-Monitoring
    url: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    summary: >
      OWASP MCP Top 10 MCP09 — Insufficient Logging & Monitoring.
      Anomalous response-time behaviour is a runtime signal that a
      logging/monitoring stack should surface. A tools/list taking
      >10s is a measurable deviation from the normal MCP handshake
      profile (<1s under healthy conditions).
  - kind: paper
    id: Cryptojacking-Detection-2020
    url: https://link.springer.com/chapter/10.1007/978-3-030-51280-4_31
    summary: >
      Cryptojacking-detection research (Springer 2020, USENIX 2021).
      Browser-based + server-side cryptojackers typically present as
      sustained CPU utilisation that also degrades the host's response
      latency. A ≥10s tools/list time is entirely within the cryptojacker
      pattern and is the rule's nominal trigger class.
  - kind: paper
    id: Slowloris-2009
    url: https://www.owasp.org/www-community/attacks/Slowloris_HTTP_DoS
    summary: >
      Slowloris-style slow HTTP attacks can cause a server to degrade
      into 10s+ response latency even under modest client load. E3 is
      a TRIPWIRE for that class of issue — not an assertion of a
      specific attack.
  - kind: spec
    id: EU-AI-Act-Art-15-Robustness
    url: https://eur-lex.europa.eu/eli/reg/2024/1689/oj
    summary: >
      EU AI Act Article 15 — Accuracy, Robustness and Cybersecurity.
      High-risk AI systems must resist errors under conditions of
      operation, including degraded performance. An MCP server with
      >10s latency on basic protocol operations is evidencing a
      robustness failure the regulation expects to be monitored.

lethal_edge_cases:
  - >
    Network latency is not server latency. A transatlantic client to a
    small-continent server can easily see 10s response on a large
    tools/list if connectivity is poor. E3 is a SIGNAL — the chain
    frames the finding as "investigate" and the remediation asks the
    reviewer to rule out network causes before acting on the server.
  - >
    Cold starts. Serverless deployments (AWS Lambda, Cloudflare
    Workers) have cold-start times that trivially exceed 10s after
    idle. The rule fires regardless because the MCP spec requires
    the handshake to complete within a reasonable window; the review
    action may be to increase the serverless warm-pool, not attribute
    to attack.
  - >
    Large tool sets. A server returning 500 tools with rich descriptions
    may legitimately take 10s+ to serialise and transmit. The chain
    calls this out so the reviewer can cross-reference E4 (excessive
    tools) before concluding the slowness is malicious.
  - >
    Response time is positive but below threshold. The threshold is
    10,000ms (legacy continuity). Rule does NOT fire below that; a
    project tightening the policy must override the threshold.
  - >
    connection_metadata is null. Silent skip — cannot assert response
    latency without a live connection observation.

edge_case_strategies:
  - threshold-10s-passthrough
  - network-latency-reviewer-note
  - silent-skip-no-connection

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - response_time_over_threshold
  location_kinds:
    - capability

obsolescence:
  retire_when: >
    The MCP runtime metric surface exposes response latency as a
    first-class field with per-call SLO tracking AND the scanner
    subscribes to that surface. Under those conditions the one-shot
    10s threshold is replaced by per-call SLO percentiles.
---

# E3 — Response Time Anomaly

**Author:** Senior MCP Supply-Chain Researcher + Senior MCP Security Engineer.
**Applies to:** Servers with `context.connection_metadata.response_time_ms > 10000`.

## Sink interpretation for a tripwire rule

E3 is informational — there is no canonical "dangerous operation" the data
reaches. The chain carries a source + a descriptive sink (the degraded
resource: CPU / event loop). This satisfies the v2 minimum-chain contract
while making the signal's meaning explicit to reviewers.

## Confidence cap: 0.65

Low — response time is a noisy signal. The 0.35 head-room reserves space
for network-side causes, cold starts, and legitimate large-payload servers.

## Severity rationale

Low. A 10s tools/list is suspicious but not conclusive; the rule's job is
to surface the observation for review, not to block deployment.
