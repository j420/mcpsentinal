---
rule_id: K7
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: ISO-27001-A.8.24
    url: https://www.iso.org/standard/82875.html
    summary: >
      ISO/IEC 27001:2022 Annex A Control 8.24 — Use of Cryptography.
      Requires cryptographic key lifecycle management including rotation
      schedules. A JWT or bearer token that does not expire (or expires
      beyond the documented rotation cadence) defeats the control by
      making rotation ineffective — the stolen token remains valid
      regardless of whether the signing key has rotated.
  - kind: spec
    id: OWASP-ASI03
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: >
      OWASP Agentic Security Initiative Top 10 — ASI03 Identity & Privilege
      Abuse. Explicitly names long-lived tokens as the primary enabler of
      persistent attacker access in agentic systems. A credential that
      outlives the operational window it was issued for is a direct control
      failure at the identity layer.
  - kind: spec
    id: CoSAI-MCP-T1
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      CoSAI MCP threat taxonomy T1 — Improper Authentication. Covers token
      lifecycle: tokens must be short-lived, must support rotation, and
      must reject expired values at the validation step. `ignoreExpiration:
      true` or equivalent disable flags violate T1 by validating tokens
      with no expiration enforcement.
  - kind: spec
    id: RFC-9700-BCP
    url: https://datatracker.ietf.org/doc/html/rfc9700
    summary: >
      OAuth 2.0 Security Best Current Practice (RFC 9700 / OAuth 2.1
      consolidation). Section on token lifetimes explicitly recommends
      access tokens be short-lived (≤1h recommended; 24h absolute ceiling
      in practice) and refresh tokens be rotation-enforced (≤30d with
      single-use semantics). Long-lived bearer tokens without rotation
      violate the BCP.
  - kind: paper
    id: Auth0-2024-token-lifetimes
    url: https://auth0.com/blog/the-ultimate-guide-to-oauth-token-lifetimes/
    summary: >
      Auth0 (2024) reference on OAuth token lifetimes, documenting that a
      stolen access token with a 24h expiry and a correctly-scoped refresh
      rotation policy yields at most 24h of attacker access. A stolen
      token with no expiry or a multi-year expiry yields persistent
      access — the functional difference is the entire control value.

lethal_edge_cases:
  - >
    Library-function alias — `const sign = jwt.sign; sign(payload, secret)`.
    The CallExpression's callee is a bare identifier `sign`, not a
    PropertyAccessExpression. The rule handles this via
    BARE_TOKEN_CREATION_CALLS (signtoken, createtoken, etc.) but does
    NOT follow arbitrary aliases. Acknowledged false-negative window for
    author-chosen local aliases; compensated by the taint-ast follow-up
    chunk planned for Phase 2.
  - >
    Expiry in a sibling config file — the token-creation call reads
    options from `config.jwt.expiresIn` where config is imported from
    a sibling file. Cross-file value resolution is out of scope; the
    rule emits a finding on the call site if the options object is
    absent/empty and records that the static analyzer could not verify
    the external configuration.
  - >
    Millisecond units — `{ expiresIn: "86400000ms" }` equals 24h but
    reads as a large integer. The rule recognises the `ms` suffix and
    divides by 1000 BEFORE comparing to the policy ceiling. A detector
    that treats "86400000" as seconds would flag a perfectly valid 24h
    token.
  - >
    Numeric literal zero as disable — `{ expiresIn: 0 }`. Some libraries
    treat zero as "no expiration"; others treat it as "expire immediately"
    (equivalent). The rule flags both as disabled-expiry and documents
    the ambiguity in the impact scenario.
  - >
    `ignoreExpiration: true` on VERIFY path, expiry present on SIGN path.
    The token has a valid `exp` claim but the verifier accepts expired
    tokens anyway. The rule flags the verify-side assignment via
    EXPIRY_DISABLE_PROPERTIES (ignoreExpiration: true) — confidence factor
    no_rotation_possible added because even a valid expiry is worthless
    when the verifier ignores it.
  - >
    Refresh-token context classification — the rule looks for "refresh"
    in the receiver / method / argument text to pick the 30-day
    threshold instead of the 24-hour threshold. False-classification
    would cause either over-firing (treating a refresh token as if it
    should live ≤24h) or under-firing (granting an access token the
    30d grace). The rule leans conservative: if any of the signals
    suggest refresh-token semantics, the looser threshold is used.
  - >
    HSM-backed rotation — a server uses short-term signing keys (the key
    itself rotates every 6 hours, independent of token expiration).
    Under this architecture, a "never-expires" JWT is bounded by the
    key's lifetime. The rule does NOT recognise this pattern (requires
    external infrastructure inspection) and may produce a false positive.
    The charter confidence cap at 0.90 reserves room for this possibility.

edge_case_strategies:
  - library-receiver-plus-method      # both receiver (jwt/jose) AND method (sign) required
  - options-object-expiry-evaluation  # walk the options ObjectLiteralExpression for expiry
  - duration-unit-parsing             # character-scan duration parser (s/m/h/d/w/y/ms)
  - disable-literal-detection         # 0/null/undefined/true/false per property sense
  - refresh-context-classification    # receiver/method/arg scan for "refresh"
  - bare-token-creation-call-set      # mintJwt/signToken/issueToken bare-call coverage
  - structural-test-file-detection    # two-signal (runner import + top-level call)

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true          # the credential-exposure moment
    mitigation: true    # rotation / key-lifecycle absence
    impact: true
  required_factors:
    - no_expiry_on_token_call | explicitly_disabled_expiry | excessive_access_token_lifetime | excessive_refresh_token_lifetime
  location_kinds:
    - source

obsolescence:
  retire_when: >
    The OAuth 2.2 specification enforces token lifetimes at the protocol
    layer — authorization servers MUST reject any token-request whose
    requested lifetime exceeds the server-configured ceiling — OR ISO
    27001 A.8.24 is superseded by a control that accepts indefinite-
    lifetime tokens paired with real-time revocation (a direction neither
    the spec nor the compliance regime is currently taking).

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# K7 — Long-Lived Tokens Without Rotation

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP server source code that creates or configures JWT /
OAuth access / OAuth refresh tokens in TypeScript or JavaScript.

## What an auditor accepts as evidence

An ISO 27001 A.8.24 auditor will not accept a rule that says "the source
code contains the number 31536000". They will accept a rule that says:

1. **Site proof** — the finding cites a `source` Location at the exact
   line of either (a) a token-creation call whose receiver + method
   match the token-library vocabulary, or (b) an expiry property
   assignment. Both forms are reproducible to the AST.

2. **Classifier proof** — the finding enumerates which expiry shape
   was observed: no expiry property, disabled-literal value, excessive
   access-class duration, or excessive refresh-class duration. The
   rule cites the parsed seconds figure so the auditor can recompute
   the ratio against the policy ceiling.

3. **Context classification** — the finding states whether the token
   was classified as access-class (24h ceiling) or refresh-class
   (30d ceiling), and enumerates the signals that drove the choice
   (receiver name, method name, argument text).

4. **Mitigation check** — the finding records the absence of a
   colocated rotation indicator. Full rotation analysis is out of
   scope for static analysis; the rule records what the scanner
   observed and directs the auditor to the rotation-check verification
   step.

5. **Impact statement** — concrete window of attacker persistence
   tied to the parsed duration, with the MCP-specific angle (every
   tool invocation in that window is attacker-controlled when the
   token carries tool authority).

## What the rule does NOT claim

- It does not follow imports. A file that reads `expiresIn` from a
  configuration module returns `no-expiry` on the call site. The
  verification step directs the auditor to resolve the config.

- It does not prove the absence of a rotation endpoint. The static
  analyzer lists what to check; full wiring confirmation is manual.

- It does not resolve aliases beyond the bare-call vocabulary. An
  author-local rename (`const s = jwt.sign; s(payload, secret)`) is
  an acknowledged false-negative window.

## Why confidence is capped at 0.90

The scanner cannot observe:

- HSM-backed signing-key rotation that bounds token lifetime
  independently of the `exp` claim;
- runtime validators wired via Express/Fastify middleware that reject
  tokens older than N minutes regardless of the `exp` claim;
- identity-provider-side enforcement (Auth0, Okta) that caps the
  issued token lifetime below what the code requests.

A maximum-confidence claim from static analysis would overstate what
is provable. 0.90 preserves room for those externalities while
signalling that the chain itself is dense with AST evidence.

## Relationship to H1 and K6

- H1 flags OAuth implementation flaws (implicit flow, ROPC,
  redirect_uri injection).
- K6 flags over-scoped tokens.
- K7 flags over-lived tokens.

All three are complementary. A server can fail all three on the same
OAuth path; a compliance scan reporting all three is not a duplicate —
each names a different attribute of the identity surface.
