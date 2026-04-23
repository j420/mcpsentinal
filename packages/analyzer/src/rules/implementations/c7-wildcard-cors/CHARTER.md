---
rule_id: C7
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: CWE-942
    url: https://cwe.mitre.org/data/definitions/942.html
    summary: >
      CWE-942 "Permissive Cross-domain Policy with Untrusted Domains".
      The canonical weakness for `Access-Control-Allow-Origin: *` /
      `cors({ origin: true })` / `cors({ origin: "*" })` configurations.
      For MCP servers exposed over HTTP — particularly Streamable HTTP
      transport — wildcard CORS lets any web origin trigger MCP tool
      calls from a logged-in user's browser.
  - kind: spec
    id: OWASP-A05-2021-Security-Misconfiguration
    url: https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
    summary: >
      OWASP Top 10:2021 A05 — Security Misconfiguration. Permissive
      CORS is one of the named examples in the A05 guidance. Combined
      with `Access-Control-Allow-Credentials: true` the configuration
      enables full cross-origin session abuse — the browser ships
      cookies / Authorization headers to anyone.
  - kind: spec
    id: OWASP-MCP07-insecure-config
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 MCP07 — Insecure Configuration. The MCP threat
      model elevates CORS misconfiguration because (a) MCP servers
      often run alongside the AI client in a workstation context where
      the user is logged in to many origins, and (b) tool invocation
      is destructive by default, so an attacker page that triggers a
      DELETE / write tool wins immediately.
  - kind: paper
    id: PortSwigger-CORS
    url: https://portswigger.net/web-security/cors
    summary: >
      PortSwigger CORS research corpus (2024 update). Catalogues every
      anti-pattern this rule targets — wildcard origin, reflected
      origin (`origin: true`), pre-flight bypass via Allow-Methods,
      Allow-Credentials with wildcard, null-origin allowlisting.

lethal_edge_cases:
  - >
    Wildcard origin paired with credentials — `cors({ origin: "*",
    credentials: true })`. Most browsers reject the combination, but
    older browsers, fetch-with-keepalive variants, and server-side
    proxies do not. The combination is also a clear signal of a
    developer who does not understand CORS — every other endpoint in
    the file deserves audit attention. The rule fires extra hard when
    both flags are set in the same options object.
  - >
    Reflected origin without an allowlist — `cors({ origin: (origin,
    cb) => cb(null, true) })` or `Access-Control-Allow-Origin: ${req.headers.origin}`.
    Functionally equivalent to wildcard but defeats a literal `"*"`
    grep. The rule must inspect the function body / template literal.
  - >
    `cors()` with no arguments — the cors npm package defaults to
    `origin: "*"`. A developer who reads the README's "Quick Start"
    inadvertently ships wildcard CORS. The rule fires on a bare cors()
    call with zero arguments.
  - >
    Per-route middleware override — a global cors() is restrictive,
    but a single `app.options("/admin", cors({ origin: "*" }))`
    overrides it for that route. The rule walks per-route registrations,
    not just the application-level middleware setup.
  - >
    Manual header set bypassing the cors module — `res.setHeader(
    "Access-Control-Allow-Origin", "*")` skips the cors module
    entirely and is invisible to any rule that only checks for cors()
    calls. The rule walks setHeader / set / header calls and checks
    the literal value of the second argument.

edge_case_strategies:
  - ast-cors-call-options          # cors({ origin: ... }) — inspect ObjectLiteralExpression
  - ast-bare-cors-call             # cors() with no arguments → defaults to wildcard
  - ast-set-header-wildcard        # res.setHeader / set / header with literal "*"
  - ast-reflected-origin           # origin: true / origin function returning true unconditionally
  - python-flask-cors              # Python flask_cors / CORS(app, origins="*") detection

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - ast_cors_pattern
    - cors_credentials_flag
    - structural_test_file_guard
  location_kinds:
    - source

obsolescence:
  retire_when: >
    The cors npm package's default origin changes from "*" to a
    non-wildcard value AND the express response API rejects "*" as a
    value for `Access-Control-Allow-Origin` when `Access-Control-
    Allow-Credentials` is true. Until both halves exist C7 retains
    high severity.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# C7 — Wildcard CORS Configuration

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP servers in TypeScript, JavaScript, or Python whose
source files are available and which expose an HTTP / WebSocket
transport (Streamable HTTP, SSE).

## What an auditor accepts as evidence

A CWE-942 / OWASP MCP07 auditor accepts a structured chain showing:

1. **Source** — a source-kind Location naming the AST node where the
   wildcard / reflected origin is configured: a CallExpression of
   `cors({ origin: ... })`, a `res.setHeader("Access-Control-Allow-
   Origin", "*")`, a Python `CORS(app, origins="*")`, or an `app.use`
   that wires a cors-style middleware with permissive defaults.

2. **Sink** — the same Location (CORS configuration is the sink
   itself; the dangerous operation is the response header that
   results). The chain `sink_type` is `network-send`.

3. **Mitigation** — recorded present/absent. "Present" means the
   options literal contains a non-wildcard `origin` (string allowlist,
   array of strings, RegExp pinned to a known host). "Absent" means
   `*`, no `origin` key (defaults to `*`), `origin: true`, a bare
   `cors()` call, or a function that returns true unconditionally.

4. **Impact** — `data-exfiltration`, scope `connected-services`. The
   canonical scenario: an attacker page in a logged-in user's browser
   triggers a tool call (DELETE / write / read-secret) and exfiltrates
   the response. Combined with `credentials: true`, full session
   abuse.

5. **Verification steps** — one for the configuration site, one for
   the credentials flag, one for any per-route override.

## Why confidence is capped at 0.90

CORS is a runtime header. A static rule cannot observe a downstream
proxy that strips Access-Control-* headers, or a feature flag that
disables the cors middleware in production. The 0.10 gap exists for
those cases.
