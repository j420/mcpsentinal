---
rule_id: O6
interface_version: v2
severity: high

threat_refs:
  - kind: cve
    id: CVE-2026-29787
    url: https://nvd.nist.gov/vuln/detail/CVE-2026-29787
  - kind: spec
    id: CWE-209
    url: https://cwe.mitre.org/data/definitions/209.html
    summary: >
      CWE-209 — Generation of Error Message Containing Sensitive
      Information. An MCP server that constructs error responses
      from OS, runtime, process, filesystem, or database internals
      hands reconnaissance data to any caller that can trigger the
      error path. The caller the rule worries about is the AI
      agent itself; the information flows straight into a tool
      response and into any downstream LLM context.
  - kind: spec
    id: OWASP-MCP04
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 — MCP04 Data Exfiltration. Fingerprinting
      error responses are the reconnaissance phase that precedes
      every targeted MCP exploit: CVE-targeted attacks against
      dependency versions, OS-specific privilege escalation,
      database auth takeover via DB-type/port/host leakage.
  - kind: spec
    id: OWASP-A05-2021
    url: https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
    summary: >
      OWASP Top 10 A05:2021 (Security Misconfiguration) lists
      verbose error messages as a canonical misconfiguration.
      In an MCP context the verbose error is a deliberate
      information-disclosure channel, not a debugging oversight.

lethal_edge_cases:
  - >
    Deliberate DB error for reconnaissance — the server catches a
    database exception and returns `{ error: err.message, driver:
    "pg", host: process.env.DATABASE_URL, port: 5432 }`. One forced
    error reveals DB type, host, port, and sometimes the full
    connection string — enough to mount a direct DB auth attack.
  - >
    File-not-found with filesystem introspection — the catch block
    returns `err.path`, `__dirname`, `process.cwd()`, or
    `os.homedir()` inside the response body. A single bad input
    reveals the server's working directory structure and the OS
    layout (Unix /home/<user> vs Windows C:\\Users\\<user>).
  - >
    Raw stack trace with dependency versions — the handler does
    `res.json({ stack: err.stack, node: process.version,
    deps: require("./package.json").dependencies })`. The returned
    versions feed a CVE-targeting campaign: the attacker now knows
    exactly which known-vulnerable versions of Express, pg,
    node-fetch, jsonwebtoken, etc. are in scope.
  - >
    Process introspection primitives in responses — `process.arch`,
    `os.arch()`, `os.platform()`, `os.release()`, `os.cpus()`,
    `os.totalmem()`, `os.networkInterfaces()`, `os.userInfo()`,
    `process.env`, `__filename`. Any of these appearing inside a
    JSON response body or an error construction is an exfiltration
    sink. A /health/detailed endpoint that returns the list
    wholesale is the CVE-2026-29787 pattern.
  - >
    Auth-oracle divergence — the server returns different error
    detail depending on whether the caller was authenticated. The
    AST walker flags distinct error-construction branches inside
    an if-auth check where one branch emits process / os / path
    metadata and the other does not.

edge_case_strategies:
  - ast-error-response-construction
  - fingerprint-surface-catalogue
  - shared-exfil-sink-anchor
  - sanitizer-adjacency-check
  - auth-branch-divergence-detection

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - fingerprint_surface_in_response
    - no_sanitizer_adjacent
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP runtimes ship a mandatory error-sanitisation shim that
    strips process / os / stack / path introspection from every
    tool response by default, OR the MCP spec declares a typed
    error channel that separates diagnostic detail from response
    payload. Neither exists as of 2026-04.
---

# O6 — Server Fingerprinting via Error Responses

## Threat Model

Every targeted MCP exploit opens with reconnaissance. The cheapest
reconnaissance primitive against an MCP server is the error path:
an attacker sends a malformed input, catches the exception
detail, and reads back OS version, Node/Python version, database
type + host + port, installed dependency versions, and filesystem
paths. CVE-2026-29787 (mcp-memory-service) shipped a
`/health/detailed` endpoint that returned the full list
unauthenticated — the canonical O6 precedent.

Distinction from **C6 (Error Leakage)**: C6 detects accidental
stack-trace exposure (a single unhandled error path that leaks
`err.stack`). O6 detects **constructed** responses that bundle
process / os / path / dependency metadata INTENTIONALLY — the
server author wrote the code that reads `process.version` and
puts it in the response. That is reconnaissance-as-a-feature,
and the remediation path is different: O6 wants the feature
removed, not just wrapped in a generic catch.

## Detection Strategy — AST Surface Match

The gather step walks the AST for two shapes:

1. **Response construction with fingerprint surface identifiers**
   — a call to `res.json()`, `res.send()`, `return { … }`, a
   `throw new Error(…)` whose payload / literal contains any
   identifier from the fingerprint surface table
   (`process.version`, `process.platform`, `process.arch`,
   `process.env`, `__dirname`, `__filename`, `os.hostname`,
   `os.networkInterfaces`, `os.cpus`, `os.userInfo`, `os.release`,
   `err.stack`, `err.path`, `db.connectionString`, etc.).

2. **Dependency-version introspection** — a response / error
   payload reads from `package.json`, `require.main.filename`,
   `require.resolve(...)`, `process.versions`, or the server's
   own `node_modules/**/package.json`.

A **sanitizer-adjacency** check inspects the enclosing function
for known sanitiser identifiers (`sanitize`, `redact`,
`scrub_error`, `pino.redact`, `sentry.scrubRequestPayload`) and
demotes the finding when one is present on the response path.

A companion catalogue hook consumes the shared
`DATA_EXFIL_SINKS` "env-var" entries so O6 narrates its findings
using the same ambient-credential vocabulary that O5 / O9 use
when the fingerprint surface happens to include `.aws`,
`.kube`, `.ssh`, or `GOOGLE_APPLICATION_CREDENTIALS` paths.

## Confidence Cap

**0.82** — the AST surface signal is strong but not airtight:
legitimate debug endpoints behind an auth gate may emit the same
identifiers without being an attack. The cap holds reviewer
headroom for the "intended diagnostic behind auth" case; the
auth-branch-divergence-detection strategy narrows the remaining
false-positive surface.
