---
rule_id: C6
interface_version: v2
severity: medium

threat_refs:
  - kind: spec
    id: CWE-209
    url: https://cwe.mitre.org/data/definitions/209.html
    summary: >
      CWE-209 "Generation of Error Message Containing Sensitive Information".
      Stack traces, file paths, package versions, hostnames, database
      schema details, and environment variables emitted to a remote
      caller hand the attacker a free recon report. The MCP threat model
      makes this worse: the AI agent itself receives the error and may
      surface internal paths in its own response, turning a backend leak
      into a user-facing one.
  - kind: spec
    id: CWE-210
    url: https://cwe.mitre.org/data/definitions/210.html
    summary: >
      CWE-210 "Self-generated Error Message Containing Sensitive
      Information". The companion weakness — an application that builds
      its own error response from internal state. Covers the
      `JSON.stringify(error)`, `traceback.format_exc()`, and
      structured-error-response patterns the rule flags in MCP servers.
  - kind: spec
    id: OWASP-A04-2021-Insecure-Design
    url: https://owasp.org/Top10/A04_2021-Insecure_Design/
    summary: >
      OWASP Top 10:2021 A04 — Insecure Design. Sending raw exceptions
      across the trust boundary is the canonical example used by the
      OWASP authors of "design-time error handling that leaks
      implementation detail". The remediation in the rule (server-side
      log + opaque client error) is taken directly from this guidance.
  - kind: paper
    id: OWASP-Error-Handling-Cheat-Sheet
    url: https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
    summary: >
      OWASP Error Handling Cheat Sheet. Catalogues the same
      anti-patterns the C6 detector targets: serialising the entire
      Error object, returning `error.stack`, leaking
      `traceback.format_exc()`, exposing express/fastify default error
      handlers in production. Used as the source for C6's expected_observation
      copy on the "send-error-to-client" verification step.

lethal_edge_cases:
  - >
    JSON.stringify(error) — the developer thinks "I'll log the whole
    object so I have something to debug with" but the JSON serializer
    walks `Error.message` AND `Error.stack` AND any custom properties,
    sending the lot to the client. A naive grep for `error.stack` would
    miss this; the rule must recognise the entire error object as the
    sensitive-data source.
  - >
    Express default error middleware in production — the developer
    relies on Express's default error handler, which sends
    `error.stack` in HTML response bodies whenever NODE_ENV !==
    "production". MCP servers shipped via Docker often forget to set
    NODE_ENV. The rule must flag any `app.use((err, req, res, next))`
    that passes the raw err to res.send/json without an env-gate.
  - >
    Python traceback.format_exc() in HTTP response — Flask/FastAPI
    convenience pattern: `return jsonify({"error":
    traceback.format_exc()})`. format_exc returns the full Python
    stack including file paths, line numbers, and surrounding code
    context. The rule covers Python through both AST property-access
    detection and direct call-expression detection.
  - >
    Reflected error properties via `...error` spread — the developer
    builds a sanitised response then accidentally spreads the entire
    error: `{ ok: false, ...err }`. Spread copies `message`, `stack`,
    `code`, and any custom enumerable properties. The rule recognises
    SpreadAssignment with an Error-typed value as a leak.
  - >
    Cause chains and aggregate errors — `new Error("...", { cause: e
    })` and AggregateError carry nested originals. JSON-serialising
    the wrapper walks the chain. The rule does not attempt to enumerate
    every wrapper class; instead it detects the wrapper's source value
    being passed to a response sink and treats that as a leak.

edge_case_strategies:
  - ast-error-to-response-sink     # walk AST: <x>.{json,send,write,status,end} call where an arg references an Error binding
  - ast-stack-property-access      # detect any `<expr>.stack` flowing into a response sink
  - python-traceback-call          # detect `traceback.format_exc()` / `traceback.print_exc()` in response body
  - spread-or-stringify-of-error   # detect JSON.stringify(err) / { ...err } / String(err) reaching a response sink
  - test-file-suppression          # AST-shape check (vitest/jest/pytest imports + describe/it) suppresses fixture noise

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - ast_match
    - error_carrier_kind
    - production_path_unguarded
    - structural_test_file_guard
  location_kinds:
    - source

obsolescence:
  retire_when: >
    Every mainstream Node.js / Python web framework refuses to
    serialise the `stack` field of an Error in its default response
    serialiser, AND the MCP SDK enforces an opaque error envelope on
    every tool response that strips internal fields by default. Until
    both halves exist, C6 retains medium severity.
---

# C6 — Error Leakage

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP servers in TypeScript, JavaScript, or Python whose
source files are available and which ship error objects across an HTTP
or MCP boundary.

## What an auditor accepts as evidence

A CWE-209 / OWASP A04 auditor accepts a structured chain showing:

1. **Source** — a source-kind Location naming the AST node where the
   sensitive data originates (the Error object itself, an `error.stack`
   property access, a `traceback.format_exc()` call, or a structured
   serialiser like `JSON.stringify(err)`).

2. **Sink** — a source-kind Location on the response method:
   `res.json` / `res.send` / `res.write` / `res.end` / `response.write` /
   `reply.send` (Fastify) / `ctx.body =` (Koa) / Python `return
   jsonify(...)` / `raise HTTPException(detail=...)`.

3. **Mitigation** — recorded present/absent. "Present" means an
   environment-gated branch (`if (process.env.NODE_ENV !==
   "production")`) wraps the leak, OR the call uses a sanitiser
   (`sanitizeError`, `formatErrorForClient`, `toSafeMessage`). Bare
   `String(err)` or `err.toString()` do NOT count — both still emit
   the full message + name.

4. **Impact** — `data-exfiltration`, scope `server-host`. The
   canonical scenario is reconnaissance: an attacker triggers a
   parsing or auth error and reads the response body to learn file
   paths, dependency versions, host name, and runtime environment.

5. **Verification steps** — one per source position + one for the
   sink + one for the absent-mitigation check.

## Why confidence is capped at 0.85

Static analysis cannot prove the control-flow gate is unreachable in
production. The 0.15 gap exists for:

- env-gated branches a downstream `if (NODE_ENV !== "production")`
  resolves at runtime;
- middleware-level error sanitisers (express-rate-limit, helmet's
  hide-powered-by, custom error handlers higher in the stack);
- response interceptors that strip `stack` after the fact.

The cap is visible as a `charter_confidence_cap` factor on every
chain whose raw confidence exceeds it.
