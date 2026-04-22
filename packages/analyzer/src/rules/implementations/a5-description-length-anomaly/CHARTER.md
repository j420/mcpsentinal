---
rule_id: A5
interface_version: v2
severity: low

threat_refs:
  - kind: spec
    id: OWASP-MCP01
    url: https://owasp.org/www-project-mcp-top-10/
    summary: >
      OWASP MCP Top 10 — MCP01 Prompt Injection. Excessively long tool
      descriptions are a known obfuscation vehicle for prompt-injection
      payloads: an attacker buries the directive after hundreds of
      characters of plausible-looking filler that a human reviewer will
      skip and an LLM will faithfully ingest.
  - kind: paper
    id: EMBRACE-THE-RED-INDIRECT-INJECTION-2024
    url: https://embracethered.com/blog/posts/2024/prompt-injection-mcp/
    summary: >
      Rehberger (2024). Demonstrates multi-paragraph injection payloads
      that pad the front with plausible tool documentation and place
      the directive at the tail — exploiting recency bias in LLM attention.
  - kind: spec
    id: MITRE-AML.T0054
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      MITRE ATLAS AML.T0054. Description-length anomaly is a weak signal on
      its own but a reliable component of multi-signal prompt-injection
      detection — the signal-to-noise ratio of genuine tool docs above
      1000 chars is demonstrably low.

lethal_edge_cases:
  - >
    Legitimate long description — a sophisticated tool may genuinely need
    hundreds of characters to explain its parameters. The rule fires only
    at LOW severity by design, acknowledging the signal is weak on its own.
  - >
    Tail injection — the first 300 chars are plausible docs, the next 800
    chars are injection filler + payload. Length alone detects this; A1
    phrase matching catches the payload on top.
  - >
    Description padding — the description contains the same sentence
    repeated 50 times to push actual safety instructions below the model's
    effective attention threshold. Character count is the diagnostic;
    de-duplication / repetition analysis is out-of-scope.

edge_case_strategies:
  - character-count-threshold   # compare description length to a calibrated threshold
  - scaling-confidence-factor   # confidence grows with how far the length exceeds the threshold

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - description_length
  location_kinds:
    - tool

obsolescence:
  retire_when: >
    The MCP spec imposes a hard length cap on tool descriptions (e.g.
    512 chars for primary description + a structured details field).

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# A5 — Description Length Anomaly

Flags tool descriptions exceeding 1000 characters at LOW severity.
A deliberately weak signal — the rule acknowledges that length alone
is not enough to classify a description as malicious, but the
anomaly is worth surfacing for review because legitimate tool
descriptions rarely exceed this threshold.

Confidence cap: 0.60. Length is a single structural signal; reviewer
headroom is essential.
