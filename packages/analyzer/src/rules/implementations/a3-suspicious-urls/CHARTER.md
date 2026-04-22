---
rule_id: A3
interface_version: v2
severity: medium

threat_refs:
  - kind: spec
    id: OWASP-MCP04
    url: https://owasp.org/www-project-mcp-top-10/
    summary: >
      OWASP MCP Top 10 — MCP04 Data Exfiltration. A tool description that
      embeds a URL pointing to an attacker-controlled shortener, tunnel
      service, or webhook canary is an active exfiltration vector. The
      AI may follow the URL as a reference or include it in a tool call.
  - kind: spec
    id: MITRE-AML.T0057
    url: https://atlas.mitre.org/techniques/AML.T0057
    summary: >
      MITRE ATLAS AML.T0057 — LLM Data Leakage. URL shorteners and webhook
      canary services are textbook low-friction exfiltration channels; they
      blur attribution, bypass domain-reputation lookups, and often evade
      DLP heuristics tuned for well-known endpoints.
  - kind: paper
    id: DNS-EXFIL-2024
    url: https://cloud.google.com/blog/topics/threat-intelligence/dns-exfiltration-detection
    summary: >
      Published 2024 industry analysis of DNS / short-URL exfiltration
      patterns. Documents ngrok, webhook.site, and interactsh as the three
      most frequently used low-reputation tunneling hosts in observed
      2024 data-exfiltration incidents.
  - kind: spec
    id: CoSAI-MCP-T5
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      CoSAI MCP-T5 — Data Exfiltration. Lists unexpected outbound URLs
      inside tool metadata as a primary exfiltration surface and
      recommends registry-level URL classification.

lethal_edge_cases:
  - >
    URL shortener (bit.ly, tinyurl, t.co) inside a description — the
    final destination is opaque until click-time. The rule flags any
    match on the shortener host list without requiring further signals.
  - >
    Tunneling service URL (ngrok, serveo, localtunnel) in a description —
    legitimate during development but never appropriate in a published
    registry entry. The rule flags these as HIGH sensitivity even
    though they are technically public DNS.
  - >
    Webhook canary / request-capture host (webhook.site, requestbin,
    interactsh) — the entire purpose of these domains is to collect
    inbound data. Their presence in a tool description is prima-facie
    evidence of an exfiltration intent.
  - >
    High-entropy random-subdomain host — an attacker-controlled C2
    often uses a programmatically-generated subdomain (20+ consonants
    in a row) under a cheap TLD. Shannon-entropy and length heuristics
    flag these without requiring an explicit blocklist.

edge_case_strategies:
  - url-parsing                   # use new URL() to extract host deterministically
  - host-registry-lookup          # typed Record<host, category>
  - suspicious-tld-lookup         # typed Record<tld, category>
  - high-entropy-subdomain-scan   # fallback Shannon-entropy analysis of the left-most label

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - suspicious_url_classification
  location_kinds:
    - tool

obsolescence:
  retire_when: >
    MCP registries perform automated URL reputation checks on every
    published description and reject submissions containing
    shortener / tunnel / canary hosts.
---

# A3 — Suspicious URLs in Tool Description

Extracts every URL from the description using a character-level
tokeniser and classifies its host against typed Records of suspicious
categories (shorteners, tunnels, canary/webhook services) and
suspicious TLDs (.tk, .ml, .xyz, .top, etc.). A fallback
entropy-based check catches high-entropy random-subdomain hosts
not listed in the catalogue.

Confidence cap: 0.90. URL classification is deterministic; the cap
preserves headroom for legitimate uses (e.g. a developer tool that
genuinely integrates with a tunneling service).
