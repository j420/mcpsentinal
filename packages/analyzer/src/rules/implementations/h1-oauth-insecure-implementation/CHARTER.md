---
rule_id: H1
interface_version: v2
severity: critical

threat_refs:
  - kind: spec
    id: RFC-9700-OAuth-2.1-BCP
    url: https://datatracker.ietf.org/doc/rfc9700/
    summary: >
      RFC 9700 — OAuth 2.1 Security Best Current Practice (Jan 2025).
      Defines the modern OAuth baseline MCP servers must implement.
      Specifically bans: (1) the implicit grant (response_type=token),
      (2) ROPC password grant (grant_type=password), (3) token storage
      in browser localStorage/sessionStorage without encryption, and
      requires: state parameter validation on every authorisation
      response, exact-string redirect_uri matching, PKCE on every
      authorisation code flow. The BCP is the canonical normative
      reference H1 cites for every vulnerability pattern it detects.
  - kind: spec
    id: MCP-Authorization-Spec
    url: https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
    summary: >
      MCP Authorization specification (June 2025 revision). Adopts
      OAuth 2.1 as the standard remote-server authentication mechanism
      and references RFC 9700 as the normative profile. An MCP server
      whose OAuth implementation violates RFC 9700 is out of
      compliance with the MCP Authorization spec itself, not merely
      with a third-party best-practice document.
  - kind: paper
    id: Portswigger-OAuth-Research-2024
    url: https://portswigger.net/web-security/oauth
    summary: >
      Portswigger Web Security Academy (2024) — catalogue of OAuth
      attacks: redirect_uri injection, state-parameter omission
      (OAuth CSRF), scope manipulation, ROPC credential exposure,
      implicit-flow token leakage via browser history and referrer.
      Each H1 detection pattern maps to a published Portswigger
      attack scenario, giving the finding a reproducible real-world
      exploit chain the auditor can walk through.
  - kind: cve
    id: CVE-2025-54135
    summary: >
      Cursor IDE CurXecute. Malicious .cursor/mcp.json with a
      project-scoped OAuth callback writable by the attacker enabled
      RCE. The CVE establishes that OAuth misconfiguration in an MCP
      client amounts to RCE on the host — H1's detection surface on
      the SERVER side catches the sister-class vulnerability.
  - kind: cve
    id: CVE-2025-54136
    summary: >
      Cursor MCPoison — silent mutation of already-approved MCP
      config. The CVE class is the OAuth-token-persistence failure
      mode: tokens stored client-side under the wrong scope or
      without rotation. H1 flags localStorage token storage directly
      to catch the server-side precondition.
  - kind: cve
    id: CVE-2025-59536
    summary: >
      Claude Code — repository-controlled .mcp.json executes server
      command before user trust dialog. Published authorisation
      without state validation is the server-side sibling: if the
      server accepts an OAuth callback without verifying the state
      parameter, an attacker fixating state can pre-authorise a
      target account. H1 flags the state-validation absence that
      enables this class.

lethal_edge_cases:
  - >
    redirect_uri assembled from user input — `redirect_uri =
    req.query.returnTo` or `req.body.redirect_uri`. Allowing the
    client to dictate the callback URL enables the "authorisation
    code injection" attack: the attacker initiates auth with their
    own redirect_uri pointing at their server, then tricks the user
    into approving. The code arrives at the attacker's server under
    the victim's identity. The rule must confirm the assignment and
    that the right-hand side references a request-scoped variable.
  - >
    Implicit flow — response_type=token (banned in OAuth 2.1 because
    the token arrives in the URL fragment, leaked through browser
    history, referrer headers, and extension access). The rule must
    match the structural equality check in code, not search for
    literal text.
  - >
    ROPC grant — grant_type=password. The client sends the user's
    raw credentials to the MCP server acting as the auth gateway.
    OAuth 2.1 explicitly bans the flow (RFC 9700 §2.4). The rule
    must fire unambiguously on this literal, because legitimate
    reasons to use ROPC after OAuth 2.1 are nil.
  - >
    Token stored in browser localStorage — `localStorage.setItem
    ("access_token", ...)`. Local storage is synchronously
    readable by any script executing on the page; any XSS payload
    exfiltrates the token. The rule must identify the setItem call
    with a token-suggesting key name.
  - >
    state parameter not validated — the server receives the
    authorisation-code callback and reads `req.query.code` without
    checking `req.query.state` against the state it issued. This
    is OAuth CSRF (Portswigger). The rule must detect this pattern
    structurally: code is extracted, state is NOT compared to any
    previously-issued value.
  - >
    scope from user input — `scope = req.body.scope` or
    `req.query.scope` sent verbatim to the token endpoint. Enables
    privilege escalation: an attacker who can initiate the flow
    submits `scope=admin full_access` and the server grants it.
    OAuth 2.1 requires servers to validate that the requested
    scope is a subset of the client's registered scope.

edge_case_strategies:
  - redirect-uri-from-request
  - implicit-flow-literal
  - ropc-grant-literal
  - localstorage-token-write
  - state-validation-absence
  - scope-from-request

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - oauth_pattern_class
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    The Model Context Protocol mandates a single audited OAuth 2.1
    library for every MCP server AND that library statically enforces
    (at import time) the RFC 9700 bans — implicit flow unavailable,
    ROPC unavailable, state validation not optional, redirect_uri
    exact-string check not bypassable. Under those conditions no
    MCP server can ship a vulnerable OAuth implementation, so H1's
    static signals become redundant.
---

# H1 — MCP OAuth 2.0 Insecure Implementation

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** Any MCP server whose source code is available to the
scanner. Primarily TypeScript/JavaScript; the same patterns surface
in Python sources and the AST walk handles both via tree-sitter.

## What an auditor accepts as evidence

A security auditor working the OAuth 2.1 BCP (RFC 9700) will not
accept "OAuth-looking code found". They will accept a finding that
says:

1. **Pattern-class proof** — the finding names which of the six
   documented patterns the AST walker matched. Each pattern is tied
   to a specific RFC 9700 clause or Portswigger attack. The pattern
   classification is what distinguishes H1 from a regex scanner that
   just sees the word "oauth".

2. **AST position proof** — the finding cites a source-kind Location
   (file:line:col) pointing at the offending assignment or call.
   The rule does NOT match in comments or string literals — AST
   walking is what buys that precision.

3. **Source-kind Location on the propagation link** — where the
   tainted value came from (e.g. `req.body`) or where the literal
   violation was declared (e.g. the line containing
   `response_type = "token"`).

4. **Impact statement** — concrete description: for redirect_uri
   injection, the attacker gains auth codes; for implicit flow, the
   user's access token leaks through referrer headers; for ROPC,
   the server receives raw user credentials that it should never
   see.

## Per-pattern honest confidence

The charter directs pattern-by-pattern confidence rather than a
single global number. The reason: some patterns are definitive
(`grant_type=password` is boolean — either the literal is there or
it is not), others require flow analysis (state-validation absence
requires confirming that no comparison of `req.query.state` happens
anywhere in the handler). The rule emits each pattern at its
individual confidence:

| Pattern                   | Confidence | Why                              |
|---------------------------|-----------:|----------------------------------|
| implicit-flow-literal     | 0.95       | Boolean presence of `"token"`   |
| ropc-grant-literal        | 0.92       | Boolean presence of `"password"`|
| localstorage-token-write  | 0.88       | Structural: setItem + key name   |
| redirect-uri-from-request | 0.85       | AST taint from request variable  |
| scope-from-request        | 0.85       | AST taint from request variable  |
| state-validation-absence  | 0.72       | Requires absence proof           |

The charter's overall cap is 0.88 — applied as a ceiling AFTER the
per-pattern assignment, so `state-validation-absence` ends up at
0.72 on its own merits and the implicit-flow literal is clamped
from 0.95 down to 0.88.

## What the rule does NOT claim

- It does not attest that the server is EXPLOITABLE today. A
  `response_type=token` literal may be behind a feature flag that
  is never enabled in production. The rule reports the presence of
  the anti-pattern; the reviewer audits reachability.
- It does not check live OAuth endpoints. That is runtime and
  out-of-scope for a static scanner.

## Relationship to other rules

- H1 is the canonical OAuth-implementation rule. Its findings
  target the server's AUTH layer.
- K6 (Overly Broad OAuth Scopes) operates on the scope values
  themselves, not the implementation pattern.
- K7 (Long-Lived Tokens Without Rotation) operates on token-TTL
  configuration.
- C5 (Hardcoded Secrets) catches OAuth client secrets committed
  to source; H1 does not.

All three may fire on the same OAuth implementation; that is the
intended multi-angle coverage.
