---
rule_id: C14
interface_version: v2
severity: critical

threat_refs:
  - kind: cve
    id: CVE-2022-21449
    url: https://nvd.nist.gov/vuln/detail/CVE-2022-21449
  - kind: paper
    id: Auth0-JWT-None-2015
    url: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
    summary: >
      Auth0 2015 disclosure: multiple JWT libraries accepted alg="none"
      when the caller omitted the algorithms array. The attacker forges
      a token with alg=none, no signature, and every claim they want —
      the library returns the claims as verified. Canonical motivation
      for pinning algorithms explicitly on every verify call.
  - kind: spec
    id: RFC-8725-JWT-BCP
    url: https://datatracker.ietf.org/doc/html/rfc8725
    summary: >
      JSON Web Token Best Current Practices (RFC 8725). Section 3.1 says
      applications MUST NOT permit alg=none, MUST NOT use HS256 with a
      public key, and MUST pin expected algorithms on verify. This rule
      surfaces all three anti-patterns in source code.
  - kind: spec
    id: OWASP-MCP07-insecure-config
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 MCP07 — Insecure Configuration. A JWT verify call
      that accepts alg=none or fails to pin algorithms is a canonical
      insecure-configuration finding for MCP servers that federate auth
      via JWT bearer tokens.

lethal_edge_cases:
  - >
    `jwt.verify(token, secret)` with NO options argument. The default
    behaviour of `jsonwebtoken` (prior to v9) accepts any algorithm in
    the token header — including `none`. The rule must fire on a
    two-argument verify call even when no algorithms option is visible.
  - >
    Algorithms array contains the literal string "none" (case-
    insensitive). Some developers ADD "none" to the allowlist during
    testing and forget to remove it. The rule does a case-insensitive
    match on every string literal inside the algorithms array.
  - >
    `algorithms: userControlledVar` — the algorithms option is a
    reference to an identifier, not an array literal. The rule cannot
    prove that the binding resolves to a safe constant; it emits the
    finding and defers to manual review via a verification step.
  - >
    `verify` override in a wrapper — `function safeVerify(token) {
    return jwt.verify(token, SECRET); }`. The rule fires on the inner
    `jwt.verify` call regardless of whether the wrapper also passes
    options — because the bug is at the library call, not at the
    wrapper.
  - >
    Test-mode flag that bypasses algorithm check leaking into prod —
    `jwt.verify(token, SECRET, process.env.JWT_NO_VERIFY ? { algorithms:
    ["none"] } : { algorithms: ["RS256"] })`. The conditional contains
    the vulnerable branch; the rule fires when either arm of a
    ternary includes the unsafe construction.
  - >
    `jwt.decode(token, { complete: true })` USED AS IF IT VERIFIED.
    `decode` does NOT verify signature — any token the attacker forges
    is parsed and trusted. The rule flags a `.decode` call whose
    result's `.payload` feeds into auth decisions.
  - >
    `PyJWT.decode(token, verify=False)` / `jwt.decode(token,
    options={"verify_signature": False})` — the Python equivalent of
    the alg=none issue. The rule normalises Python and JS on the same
    AST structural pattern: any verify argument that evaluates to
    False.
  - >
    `ignoreExpiration: true` — a JWT with an expiry that passed 3
    years ago still validates. Less severe than alg=none (signature
    is still checked) but still a finding — charter keeps this at
    severity "high" rather than "critical".

edge_case_strategies:
  - verify-without-options
  - algorithms-contains-none
  - algorithms-reference-not-literal
  - wrapper-verify-override
  - conditional-unsafe-branch
  - decode-used-as-verify
  - pyjwt-verify-false
  - ignore-expiration-true

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - jwt_call_identity
    - algorithms_option_inspection
    - charter_confidence_cap
  location_kinds:
    - source

obsolescence:
  retire_when: >
    Every mainstream JWT library REFUSES to operate without an
    explicit algorithms pin at the TYPE level (compile error on
    jwt.verify(token, secret) with no options) — AND RFC 8725 becomes
    a MUST in the baseline MCP authorisation spec. Until both, C14
    retains critical severity on the clearly-unsafe patterns.
---

# C14 — JWT Algorithm Confusion / None Algorithm Attack

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP servers in TypeScript, JavaScript, or Python whose
source files call a JWT verify or decode API on incoming tokens.

## What an auditor accepts as evidence

An OWASP MCP07 / RFC 8725 auditor accepts:

1. **Source position** — a source-kind Location on the library call
   (`jwt.verify` / `jsonwebtoken.verify` / `jose.jwtVerify` /
   `jwt.decode` / `PyJWT.decode`).

2. **Structural finding** — the specific anti-pattern the call exhibits:
   no options argument, algorithms array containing "none",
   algorithms option as a variable reference, `verify_signature: False`,
   `ignoreExpiration: true`, use of `decode` where `verify` was needed.

3. **Mitigation** — the chain records whether a sibling call
   demonstrably pins algorithms (a correctly-configured `jwt.verify`
   in the same file implies the developer knows the correct shape,
   downgrading novelty of the bug to "implementation inconsistency"
   rather than "missing knowledge").

4. **Impact** — `session-hijack` / `privilege-escalation`, scope
   `user-data` / `connected-services`. A forged `alg=none` token
   passes validation with arbitrary claims — authentication bypass.

5. **Verification steps** — one per observed anti-pattern, each with
   a source-kind Location so an auditor can open the call site and
   confirm the charter-named edge case.

## What the rule does NOT claim

- It does not validate signed tokens — no runtime behaviour.
- It does not flag `jwt.decode(token, {complete: true})` unless
  the return value structurally feeds into an authorisation
  decision (we only flag it when the next AST node uses the
  decoded payload in an `if (payload.isAdmin)` style shape; the
  structural check is conservative).
- It does not model middleware chains — if algorithm pinning lives
  in a middleware layer the file-local call cannot see, the rule
  still fires with a charter_confidence_cap note.

## Why confidence is capped at 0.92

AST structural detection of the jwt.verify call shape is deterministic,
but the 0.08 gap accounts for middleware-based algorithm pinning
(express-jwt, fastify-jwt, NestJS AuthGuard) that wraps the lib call in
a configuration the static analyser cannot see. The cap is visible on
the chain as `charter_confidence_cap`.
