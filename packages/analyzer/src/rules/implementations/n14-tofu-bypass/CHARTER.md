---
rule_id: N14
interface_version: v2
severity: critical
owasp: MCP10-supply-chain
mitre: AML.T0054
risk_domain: protocol-transport

threat_refs:
  - kind: paper
    id: SSH-TOFU-Research
    url: https://tools.ietf.org/html/rfc4251
    summary: >
      Trust-On-First-Use (TOFU) originated with SSH and PGP: on first
      connection the client pins the server's public-key fingerprint;
      subsequent connections verify. The canonical weakness is that the
      FIRST connection has nothing to verify against — an attacker
      positioned on the network at first-connect time can pin a
      malicious key and every subsequent "verification" succeeds
      against the attacker's key.
  - kind: paper
    id: MCP-TOFU-Applied-2026
    url: https://modelcontextprotocol.io/blog/tofu-considerations
    summary: >
      MCP servers that implement TOFU-style identity binding on first
      connect (common pattern for self-hosted MCP servers behind
      reverse proxies) inherit the same bootstrap weakness. The rule
      flags TWO specific failure modes: (a) clients that bypass or
      disable fingerprint pinning after the first connect, and
      (b) servers / clients that accept any first-connect identity
      without operator confirmation.
  - kind: spec
    id: MITRE-ATLAS-AML-T0054
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      TOFU bypass is the MCP-transport realisation of a substitution-
      based prompt-injection precondition: by swapping the server
      identity after initial pin, the adversary makes every later
      tools/list response an attacker-chosen payload, even though
      the client's session state considers the server "verified".

lethal_edge_cases:
  - >
    Pinning is explicitly skipped or disabled by a flag. Code path
    `ignoreFingerprint: true` / `skipHostKeyCheck` / `verify: false`
    passes on every connection. This is the "security theatre" case
    — the variable suggests a trust check happens, but the implementation
    drops it. Direct indicator of a willful bypass.
  - >
    First-connect accept-any (no operator prompt). The server / client
    accepts whatever identity the peer presents on first connect and
    stores it without human verification. Attacker who positions at
    first connect plants their own identity. The bootstrap window is
    small but catastrophic.
  - >
    Fingerprint store is mutable at runtime (the "renew-pinning"
    anti-pattern). Code that re-pins on mismatch rather than rejecting.
    A reachable reset path makes the pinning irrelevant — the attacker
    just triggers a re-pin to their own key.
  - >
    Known_hosts / fingerprint file writeable by the agent process with
    no provenance check. A compromised tool that can write to the
    filesystem can re-pin the server. The attacker does not need the
    network position — an in-process-compromise suffices. Cross-
    reference J1 (cross-agent config poisoning) for the broader class.

edge_case_strategies:
  - explicit-pinning-bypass-scan
  - first-connect-accept-any-scan
  - mutable-fingerprint-store-scan
  - writeable-pin-file-scan

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - pinning_bypass_detected
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP SDKs ship with out-of-band key-distribution mechanisms that
    eliminate TOFU at bootstrap. Until then, server-side avoidance of
    the bypass patterns is the defence.
---

# N14 — Trust-On-First-Use Bypass (TOFU)

Structural. Honest-refusal when neither first-connect nor pinning
fragments are present. Confidence cap 0.78.
