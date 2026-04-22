---
rule_id: L7
interface_version: v2
severity: critical
owasp: MCP06-excessive-permissions
mitre: AML.T0054
risk_domain: supply-chain-security

threat_refs:
  - kind: paper
    id: arxiv-2509.24272-when-mcp-servers-attack
    url: https://arxiv.org/abs/2509.24272
    summary: >
      "When MCP Servers Attack" (arXiv 2509.24272, September 2025) — a
      comprehensive taxonomy of MCP attack surfaces. Section 4.3 describes
      transitive delegation as the canonical "confused deputy" problem
      applied to MCP: a server the user approves secretly holds a client
      connection to another, unapproved server, forwarding requests and
      credentials across a trust boundary the user never consented to.
  - kind: paper
    id: praetorian-mcp-attack-surface-2026
    url: https://www.praetorian.com/blog/mcp-server-security-hidden-ai-attack-surface
    summary: >
      Praetorian Labs "MCP Server Security: The Hidden AI Attack Surface"
      (February 2026). Catalogues real-world MCP gateways and aggregators
      that import both server and client SDKs. The report shows that a
      single compromised upstream MCP server reaches every downstream AI
      client via the proxy's trust — the proxy is the confused deputy.
  - kind: paper
    id: flowhunt-confused-deputy-mcp-2025
    url: https://www.flowhunt.io/blog/mcp-authentication-confused-deputy-problem
    summary: >
      FlowHunt "MCP Authentication: The Confused Deputy Problem" (late 2025).
      Walks through the credential-forwarding failure mode: an MCP gateway
      approved by the user to read a single calendar passes the user's OAuth
      bearer token to every backend MCP server it proxies, defeating the
      scoped-consent property the user believed they authorised.

lethal_edge_cases:
  - >
    Dynamic import of the client SDK — the server uses
    `await import("@modelcontextprotocol/sdk/client/index.js")` inside a
    deferred code path, so a static `import` declaration scan misses it.
    The rule must also match call-expression imports whose argument text
    contains the MCP client SDK subpath, not only top-of-file import
    declarations.
  - >
    Aliased client construction — the server imports `Client as MCPC` from
    the SDK and instantiates it inside a tool handler. A name-based
    `Client` identifier search misses the alias. The rule must resolve the
    imported binding name through the import specifier and flag ANY
    construction whose constructor was imported from the MCP client SDK,
    regardless of local alias.
  - >
    Transport-only import (no explicit `Client`) — a compromised module
    imports only `StdioClientTransport` / `SSEClientTransport` /
    `StreamableHTTPClientTransport` and instantiates them directly. The
    transport classes are sufficient to open a remote MCP connection; the
    rule must treat them as equivalent to the `Client` import for
    detection purposes, not ignore them because `Client` is absent.
  - >
    Credential-forwarding proxy — the server accepts a bearer token from
    the incoming MCP request and passes it unchanged to the upstream
    client connection (`headers: { authorization: req.headers.auth }`).
    This is the specific "confused deputy" pattern FlowHunt describes.
    The rule must raise severity / confidence when an incoming-request
    credential reaches the outbound-client arguments, not merely when the
    two SDKs coexist in the same file.
  - >
    Test-file camouflage — integration tests legitimately import both
    server and client SDKs to verify handshake behaviour. A path-suffix
    `*.test.ts` check catches most, but attacker code can ship as
    `src/handlers/proxy.ts` and contain a vitest `describe` wrapper to
    masquerade as a test. The rule must use a structural test-file
    heuristic (runner import + top-level `describe` / `it`) rather than
    a filename heuristic.
  - >
    Proxy via a delegating framework — the server uses `mcp-proxy` or a
    similar helper package whose constructor hides the client import. A
    rule that only inspects the server's own file misses this. The rule
    reports delegation when ANY imported package name contains known
    proxy-framework substrings (mcp-proxy, mcp-bridge, mcp-gateway) even
    when no SDK client import is directly visible.

edge_case_strategies:
  - ast-dual-sdk-import
  - alias-binding-resolution
  - transport-class-equivalence
  - credential-forwarding-taint
  - structural-test-file-exclusion
  - proxy-framework-substring

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - dual_sdk_import
    - client_or_transport_instantiation
    - credential_forwarding_observed
  location_kinds:
    - source

obsolescence:
  retire_when: >
    The MCP specification adds a first-class "delegated-server" manifest
    field that requires a server to declare every downstream MCP server
    it proxies, AND MCP clients enforce the manifest as part of the
    tools/list approval UI. At that point a transitive client inside a
    server is either declared (and approved by the user) or rejected at
    the protocol layer — static detection is no longer needed.

mutations_survived:
  - reorder-object-properties
mutations_acknowledged_blind:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
---

# L7 — Transitive MCP Delegation

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP server source code that imports the MCP SDK or any
known MCP proxy framework.

## What an auditor accepts as evidence

An ISO 27001 A.5.17 / CoSAI MCP-T1 auditor will not accept "the file
mentions `Client`". They will accept:

1. **Source proof** — an AST-visible import (declaration OR dynamic
   `import()` call) whose specifier string contains the MCP client SDK
   subpath (`@modelcontextprotocol/sdk/client`) or a known proxy
   framework name. The `source`-kind Location points to the import
   statement.

2. **Propagation proof** — a construction of the imported client
   (`new Client(...)`, `new StdioClientTransport(...)`, etc.) inside a
   tool handler or module-level initialiser, with a separate source-kind
   Location. This is the transitive step: the server now holds a
   downstream connection the user never authorised.

3. **Sink proof** — either (a) a `connect()` / `callTool()` call against
   the constructed client (full proxy shape), OR (b) an outgoing request
   carrying a header whose value is derived from the incoming request's
   credential (the credential-forwarding shape). The rule raises severity
   to critical when the credential-forwarding shape fires.

4. **Mitigation check** — the rule reports whether the server declares a
   `delegated_servers` field in its metadata / package.json. Absence is
   the finding; presence reduces confidence because the user can inspect
   the declared list.

5. **Impact** — the confused-deputy scenario is concrete: a compromised
   upstream server injects a poisoned tool description, the proxy relays
   it to the AI client, the AI client approves an action under the
   PROXY's name even though the instruction came from the unapproved
   upstream. This is the exact propagation pattern Praetorian documents.

## Why confidence is capped at 0.85

Integration test files legitimately import both SDKs. Even with the
structural test-file heuristic, some production code looks a lot like a
test harness (tools that probe remote MCP servers as part of their
declared capability). The 0.85 cap preserves room for that residual
uncertainty — the finding is high confidence, not absolute.
