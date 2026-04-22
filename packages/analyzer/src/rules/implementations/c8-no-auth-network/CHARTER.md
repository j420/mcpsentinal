---
rule_id: C8
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: CWE-306
    url: https://cwe.mitre.org/data/definitions/306.html
    summary: >
      CWE-306 "Missing Authentication for Critical Function". A
      network-exposed MCP server that accepts tool invocations without
      authentication is a textbook CWE-306 instance: any caller on the
      network can drive the AI's destructive actions. The MCP spec is
      explicit that tools are destructive by default.
  - kind: spec
    id: OWASP-A07-2021-Identification-Authentication-Failures
    url: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
    summary: >
      OWASP Top 10:2021 A07. The "permits unauthenticated access to
      sensitive operations" anti-pattern. Listed as one of the named
      symptoms in the A07 guidance. For MCP, "sensitive operation" =
      every tool, because tools execute on behalf of the user.
  - kind: spec
    id: OWASP-MCP07-insecure-config
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 MCP07 — Insecure Configuration. Binding to
      0.0.0.0 without authentication is the canonical example used in
      the MCP07 narrative. Common cause: a developer ports a stdio MCP
      server to Streamable HTTP and forgets that the network transport
      requires its own auth layer.
  - kind: paper
    id: CSA-MCP-Security-Whitepaper-2025
    url: https://cloudsecurityalliance.org/research/topics/multi-agent-threat-modeling
    summary: >
      CSA MCP security guidance (2025). Lists "internet-exposed MCP
      server with no authentication" as a top operational risk. The
      paper's specific example — a Docker-deployed MCP server with
      EXPOSE 8080 and no app-level auth — is exactly the pattern this
      rule detects.

lethal_edge_cases:
  - >
    `app.listen(3000, "0.0.0.0")` with no `app.use(authMiddleware)` ever
    registered. The string "0.0.0.0" is the universal "all
    interfaces" address. Any caller on the network can issue tool
    invocations.
  - >
    Default-host listen — `app.listen(3000)` with no host argument
    binds to 0.0.0.0 on most stacks (express, koa, fastify). A
    developer who only writes the port number ships an
    internet-exposed server by default.
  - >
    Token-from-query-string masquerading as auth — the file calls
    `verifyToken(req.query.token)` but the token has no rotation, no
    expiry, and is logged by every reverse proxy. The rule does not
    treat query-string-token-only patterns as real auth.
  - >
    Auth middleware imported but never wired — `import { authMiddleware
    } from "./auth.js"` is present but no `app.use(authMiddleware)` /
    `app.use(passport.authenticate(...))` call follows. The rule
    walks the AST for actual `use()` calls, not import presence.
  - >
    Per-route auth on most routes but a single unauthenticated route
    handles tool invocation. `app.post("/tool", handler)` with no
    auth middleware on that one route is the leak even when every
    other route is protected. The rule examines each route
    registration independently.

edge_case_strategies:
  - ast-listen-call                # detect `<server>.listen(port[, host])` and check host
  - ast-host-resolution            # bare `listen(port)` defaults to 0.0.0.0
  - ast-auth-middleware-check      # check whether `app.use(<auth>)` is present in same scope
  - ast-per-route-auth             # detect routes where the handler has no auth middleware
  - python-uvicorn-host            # uvicorn.run(app, host="0.0.0.0", port=...) detection

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - ast_network_bind
    - auth_middleware_search
    - structural_test_file_guard
  location_kinds:
    - source

obsolescence:
  retire_when: >
    The MCP SDK refuses to start a Streamable HTTP transport without
    a configured authenticator AND the express / fastify / koa
    defaults bind to 127.0.0.1 instead of 0.0.0.0. Until both halves
    exist, C8 retains high severity.
---

# C8 — No Authentication on Network-Exposed Server

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP servers in TypeScript, JavaScript, or Python whose
source files are available and which start an HTTP / WebSocket
listener.

## What an auditor accepts as evidence

A CWE-306 / OWASP MCP07 auditor accepts a structured chain showing:

1. **Source** — a source-kind Location naming the AST node where the
   server binds to a network interface: a `.listen(port[, host])`
   call, `.bind(addr)`, `uvicorn.run(...)`, `gunicorn` start.

2. **Sink** — the same Location: the bind itself is the dangerous
   operation when no authentication wraps it. The chain `sink_type`
   is `network-send`.

3. **Mitigation** — recorded present/absent. "Present" means the
   surrounding module wires an auth middleware via `app.use(...)`,
   `app.use(passport.authenticate(...))`, FastAPI `Depends(...)` on
   each protected endpoint, etc. "Absent" means no such call is
   visible in the source — even if a module-level import exists.

4. **Impact** — `privilege-escalation`, scope `connected-services`.
   Any caller on the network drives the AI's tool actions.

5. **Verification steps** — one for the bind, one for the auth
   search, one for environment-binding (whether localhost-only is
   intended).

## Why confidence is capped at 0.85

A static rule cannot observe network-level isolation: a Docker
network that exposes the port only to a sidecar reverse proxy that
performs auth is a real defence. Likewise an upstream service mesh
with mTLS. The 0.15 gap is reserved for those cases.
