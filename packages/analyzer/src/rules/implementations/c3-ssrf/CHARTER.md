---
rule_id: C3
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: CWE-918
    url: https://cwe.mitre.org/data/definitions/918.html
    summary: >
      CWE-918 "Server-Side Request Forgery (SSRF)". The canonical weakness
      class for this rule. The MCP server fetches a URL whose host /
      path / scheme component is attacker-controlled. The classic 2024–
      2026 cloud impact is exfiltration of IAM credentials from the
      instance metadata service (169.254.169.254 on AWS, metadata.google.
      internal on GCP, 169.254.169.254 on Azure) — one HTTP call away
      from full account takeover.
  - kind: spec
    id: OWASP-MCP04-data-exfiltration
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 MCP04 — Data Exfiltration. SSRF is the single
      highest-yield exfiltration primitive in the MCP threat model
      because MCP servers run inside cloud and corporate networks and
      reach internal services (Kubernetes API, Redis, IMDS, Vault) the
      AI client itself cannot reach. The MCP server is a trusted hop;
      SSRF turns it into the attacker's hop.
  - kind: spec
    id: OWASP-A10-2021
    url: https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
    summary: >
      OWASP Top 10:2021 A10 — Server-Side Request Forgery. Promoted to
      its own Top 10 category in 2021 after years as a sub-class of
      injection. The OWASP guidance is explicit: schemes other than
      http/https (file://, gopher://, dict://, ftp://) must be rejected;
      DNS resolution must be performed once and the resolved IP
      checked against private-range allowlists; redirects must not be
      followed across trust boundaries.
  - kind: paper
    id: PortSwigger-SSRF-2024
    url: https://portswigger.net/web-security/ssrf
    summary: >
      PortSwigger SSRF research (2024 update). Canonical reference for
      DNS-rebinding, IPv6 bypasses (e.g. ::ffff:169.254.169.254),
      decimal/octal/hex IP encodings, and IDN homoglyph host attacks
      that defeat naive deny-list checks. Cited because the lethal
      edge cases below are drawn from this corpus.

lethal_edge_cases:
  - >
    IMDS / cloud-metadata target — req.body.url ends up as
    http://169.254.169.254/latest/meta-data/iam/security-credentials/.
    Single HTTP call returns short-lived AWS credentials the MCP host
    is running with. The static analyser cannot resolve the value but
    can prove the URL is attacker-controlled, which is sufficient for a
    high-severity finding.
  - >
    DNS rebinding — attacker controls a hostname that resolves to a
    public IP on first lookup (passes any allowlist) and to
    169.254.169.254 on the second lookup the HTTP client performs
    immediately afterwards. Deny-listing 169.254.169.254 by literal IP
    does NOT mitigate this — the DNS resolution happens inside the
    HTTP client. The rule's mitigation check accepts only resolution-
    pinning helpers (resolve once and pass the IP to the request), not
    string-level allowlists.
  - >
    URL parser confusion — attacker supplies a URL the WHATWG URL
    parser interprets as one host but the underlying http library
    resolves as another (CVE class: CVE-2022-23540 / CVE-2018-3727 and
    countless siblings). e.g. http://evil.com#@169.254.169.254/. Static
    analysis cannot prove the parser is consistent with the HTTP
    library; the rule treats any user-controlled URL component as
    tainted regardless of intermediate "validation" calls that don't
    canonicalise the host.
  - >
    Scheme smuggling — attacker supplies file:///etc/passwd or
    gopher://internal/...%0d%0aHELO. Many HTTP libraries (axios with
    custom adapters, node-fetch with custom agents) silently honour
    non-http schemes. The rule fires whenever the URL string is
    attacker-controlled without an explicit scheme allowlist on the
    code path — bare `new URL(userInput)` does NOT enforce a scheme
    allowlist.
  - >
    Decimal / octal / hex IP encoding — http://2852039166/ resolves to
    169.254.169.254 on most stacks; http://0xa9fea9fe/ does the same.
    A regex-based allow/deny on dotted-quad strings misses these. The
    rule does not attempt to enumerate the encodings — it stays at the
    layer above by demanding a charter-audited resolver/allowlister on
    the path; presence of bare `URL` / `URL.parse` is NOT sufficient.

edge_case_strategies:
  - ast-taint-ssrf-sink                 # analyzeASTTaint sink.category === "ssrf"
  - lightweight-url-request-fallback    # analyzeTaint sink.category === "url_request"
  - charter-audited-allowlister         # only resolve+pin / allowlist helpers count as mitigation
  - dns-rebinding-aware                 # bare regex/string allowlists are NOT recognised mitigations

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - ast_confirmed
    - lightweight_taint_fallback
    - interprocedural_hops
    - unverified_sanitizer_identity
    - charter_confidence_cap
  location_kinds:
    - source

obsolescence:
  retire_when: >
    The MCP SDK exposes a first-class `fetchUrl(url, { allowedHosts })`
    helper that REQUIRES an allowedHosts allowlist, performs DNS
    resolution once, pins the resolved IP for the request, and rejects
    private/loopback/link-local ranges by default — AND the SDK
    generators emit that helper for every tool whose schema declares
    a URL parameter. Until both halves exist C3 retains high severity.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
mutations_acknowledged_blind: []
---

# C3 — Server-Side Request Forgery (Taint-Aware)

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP servers in TypeScript, JavaScript, or Python whose
source files are available and which call an HTTP / fetch / requests
API.

## What an auditor accepts as evidence

A CWE-918 / OWASP MCP04 auditor accepts a structured chain showing:

1. **Source** — a source-kind Location naming the AST node where
   untrusted data enters (`req.body.*`, `req.query.url`, MCP tool
   argument, `process.env.TARGET_URL`, `request.form[...]`).

2. **Propagation** — one link per hop (assignment, destructure,
   template-embed, function-call, return). Direct single-line flows
   have zero propagation links and exploitability = "trivial".

3. **Sink** — a source-kind Location on the HTTP call: `fetch`,
   `axios.{get,post,put,...}`, `http.request`, `https.request`,
   `request`, `got`, Python `requests.{get,post,...}`, `urllib.request.urlopen`,
   `httpx.{get,post,...}`. The chain `sink_type` is `network-send`.

4. **Mitigation** — recorded present/absent. "Present" means a
   charter-audited allow-/deny-listing helper lies on the path
   (`isAllowedUrl`, `assertPublicHost`, `pinResolvedIp`, `safeFetch`).
   `URL` / `URL.parse` / `new URL()` alone are NOT on the charter list
   because none of them check the resolved IP against private ranges.

5. **Impact** — `data-exfiltration`, scope `connected-services`. The
   canonical scenario is IMDS credential theft (AWS / GCP / Azure
   metadata services), with secondary scenarios for internal-API
   access (Kubernetes, Redis, internal admin) and out-of-band
   exfiltration via DNS-resolving HTTP libraries.

6. **Verification steps** — one per AST hop + an explicit step for
   the sanitiser (or its absence).

## Why confidence is capped at 0.92

AST-confirmed in-file taint to a known HTTP sink is the strongest
static proof. The 0.08 gap exists for:

- runtime-resolved allowlists the static analyser cannot see
  (allowlist loaded from config at startup);
- middleware-level URL filters (egress proxies, service-mesh egress
  policies);
- tagged-template HTTP DSLs that parameterise the host before the
  static reader sees it.

The cap is visible as a `charter_confidence_cap` factor on every
AST-confirmed chain whose raw confidence exceeds it.
