---
rule_id: K6
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: ISO-27001-A.5.15
    url: https://www.iso.org/standard/82875.html
    summary: >
      ISO/IEC 27001:2022 Annex A Control 5.15 — Access control. Requires
      that access rights be based on the principle of least privilege.
      An OAuth scope declaration that requests wildcard, admin, or
      read:all / write:all grants exceeds the authority the MCP server
      functionally requires. The control fails at the REQUEST stage: once
      the token is issued with the broad scope, no runtime authorization
      check downstream can shrink it.
  - kind: spec
    id: ISO-27001-A.5.18
    url: https://www.iso.org/standard/82875.html
    summary: >
      ISO/IEC 27001:2022 Annex A Control 5.18 — Access rights. Access
      rights must be the minimum necessary. OAuth scopes are the
      access-rights declaration for delegated access; broad scopes
      encode excessive rights by definition.
  - kind: spec
    id: OWASP-ASI03
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: >
      OWASP Agentic Security Initiative Top 10 — ASI03 Identity & Privilege
      Abuse. Calls out over-scoped OAuth tokens as the primary enabler of
      lateral escalation in agentic systems: a leaked token with wildcard
      or admin scope lets the attacker inherit the full scope of the
      identity, not just the functionality the MCP server exposed.
  - kind: spec
    id: CoSAI-MCP-T2
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      CoSAI MCP threat taxonomy T2 — Missing Access Control. Lists
      "excessive delegated permissions" as a distinct sub-threat from T1
      (authentication). An MCP server with proper authentication but
      over-scoped tokens still fails T2.
  - kind: spec
    id: CoSAI-MCP-T1
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      CoSAI MCP threat taxonomy T1 — Improper Authentication. Scope
      injection (a user-controlled scope value) is explicitly named as
      a T1 sub-threat: the server accepts the caller's claim about
      what permissions to grant, rather than mapping it to a
      server-enforced allowlist.
  - kind: spec
    id: RFC-6749-S3.3
    url: https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
    summary: >
      OAuth 2.0 Framework, Section 3.3 — Access Token Scope. Specifies
      that the authorization server MUST inform the client about the
      scope granted; RFC 6749 and RFC 9700 (OAuth 2.1 consolidation)
      both REQUIRE that servers validate requested scopes against a
      permitted-scope list rather than accept them unchecked.

lethal_edge_cases:
  - >
    Ambiguous property name with OAuth context — a property named
    `permissions` alone is not OAuth-specific (filesystems use it,
    RBAC uses it). The rule must distinguish the OAuth-context case:
    `permissions` alongside `client_id` and `token_endpoint` in the
    same object literal IS OAuth; `permissions` alongside `path` and
    `mode` is a filesystem permissions field. A detector that fires on
    the name alone produces noise; a detector that skips all ambiguous
    names produces false negatives. Two-signal classification is required.
  - >
    Array-form vs space-separated string — OAuth servers accept both
    `scope: "read write admin"` and `scopes: ["read", "write", "admin"]`.
    A detector that only reads string literals misses half of real-world
    code. The rule must split string values on whitespace / comma AND
    iterate array literal elements.
  - >
    Colon/dot-delimited admin suffix — GitHub uses `admin:org`, GCP uses
    `bigquery.admin`, M365 uses `Sites.FullControl.All`. A detector with
    exact-match vocabulary misses these; a detector using a substring
    test (admin anywhere) over-fires on `admin_panel_read`. The rule
    splits on ":" and "." and checks the LAST segment only against a
    curated set.
  - >
    User-controlled scope via generic receiver — `ctx.body.scope` is
    user-controlled, but `ctx.user.scope` is server-resolved. The rule
    must require a "user-input chain marker" (body, query, params,
    headers, searchparams, url, input) in the property chain when the
    base receiver is generic (ctx, context, event, args).
  - >
    Narrowing downstream — an initial `scope: "admin"` declaration that
    is overwritten by a role-based switch in the next 10 lines is still
    a finding at the declaration site. The rule emits the finding AND
    marks the mitigation as absent-at-this-location; it does not do full
    flow analysis to retract the finding. Charter records this as a
    known false-positive window: when a static analyzer sees a broad
    scope on a line, a reviewer can still confirm narrowing downstream
    before dismissing the finding.
  - >
    OAuth scope embedded in a TemplateExpression — `` scope: `read ${ROLE}` ``.
    The literal prefix is safe, the interpolation is user/role-dependent.
    The rule walks TemplateExpression spans and flags when any span
    resolves to a user-input source; it does not attempt to classify
    the user's intent.
  - >
    Scope assigned via spread — `config = { ...defaults, ...userOptions }`.
    Neither the receiver nor the concrete keys are visible at the
    assignment site. Static analyzer limitation: rule does NOT attempt
    spread tracking. Acknowledged false-negative window; compensated
    by rules J1/L11 which flag the spread pattern itself as a
    config-poisoning surface.

edge_case_strategies:
  - ambiguous-name-with-context-confirmation   # ambiguous name fires only with OAuth sibling keys
  - whitespace-and-array-tokenisation          # string split + array iteration
  - colon-dot-suffix-classification            # structural last-segment check
  - generic-receiver-chain-marker-required     # ctx/event/args need body|query|params in chain
  - template-span-user-input-detection         # walks TemplateExpression spans
  - structural-test-file-detection             # two-signal (runner import + top-level call)

evidence_contract:
  minimum_chain:
    source: true
    propagation: true          # scope literal flows unchanged from declaration to token request
    sink: true                 # privilege-grant at token issuance
    mitigation: true           # input-validation or scope-narrowing
    impact: true
  required_factors:
    - broad_scope_wildcard | broad_scope_admin | broad_scope_broad
    - user_controlled_scope | oauth_context_confirmed | multiple_broad_entries
  location_kinds:
    - source                   # file:line:col for every scope assignment

obsolescence:
  retire_when: >
    The MCP specification mandates that authorization servers MUST reject
    any token request carrying a scope not present in a server-registered
    permitted-scopes allowlist (spec-level enforcement replacing
    application-level checks) — OR OAuth 2.1 supersedes OAuth 2.0 with a
    mandatory scope-mapping step that renders client-supplied scopes
    advisory only. Neither has happened as of 2026-04.
---

# K6 — Overly Broad OAuth Scopes

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP server source code that declares OAuth scopes in
token requests, OAuth provider configuration, or authorization helpers.

## What an auditor accepts as evidence

A CISO reviewing an ISO 27001 A.5.15 claim will not accept a rule that
says "the source code contains the string 'admin'". They will accept a
rule that says:

1. **Assignment proof** — the finding cites a `source` Location at the
   exact line and column of an OAuth scope assignment (a property in an
   object literal with a sibling OAuth context key, OR a binary
   assignment whose target tail is in the OAuth scope vocabulary, OR a
   variable initialiser whose name is in the vocabulary).

2. **Token classification** — the finding enumerates which scope tokens
   were flagged and why: exact wildcard match, exact admin match, exact
   broad-prefixed match, or structural colon/dot suffix check. The
   rationale is reproducible — another auditor running the same
   vocabulary reaches the same classification.

3. **User-input assessment** — the finding states whether the value
   resolves to a user-input source and, if so, names the property
   chain. An organisation whose MCP server accepts `ctx.body.scope`
   unchanged has a different control failure from one that hard-codes
   `scope: "*"`; the rule distinguishes the two.

4. **Mitigation check** — the finding records the absence (or presence)
   of input validation / allowlist intersection at the assignment
   location. Presence downgrades severity but does not silence — a
   broad scope that is sometimes narrowed is still a compliance
   exposure.

5. **Impact statement** — concrete consequence: what an attacker with
   the issued token can do, tied explicitly to the identity
   provider's documented authority model (wildcard = every permission,
   admin = full administrative authority, broad = cross-resource
   access).

## What the rule does NOT claim

- It does not perform full data-flow analysis. A broad scope at
  declaration that is narrowed downstream by a role-based switch is
  still flagged with the mitigation recorded as absent AT THIS
  LOCATION. The reviewer may confirm the narrowing and dismiss.

- It does not track spread-operator shapes (`{ ...defaults, ...user }`).
  Files built from spreads are an acknowledged false-negative window;
  rules J1 / L11 (config poisoning) cover the spread surface.

- It does not check the identity provider's actual scope catalogue
  (is `admin:org` a real GitHub scope?). The vocabulary is intentionally
  generic: real identity providers have broader scope registries than
  we can enumerate; the rule classifies based on structural semantics
  (wildcard, admin suffix, broad prefix) that hold across providers.

## Why confidence is capped at 0.92

Static analysis cannot observe:

- server-side scope narrowing that an authorization middleware enforces
  after the file under review hands off the request;

- spread-operator reconciliation that resolves at runtime to a narrower
  scope set than any single literal in the source;

- production deployment secrets (environment variables) that may
  substitute a narrower scope before the token request is sent.

A maximum-confidence claim from static analysis would overstate what is
provable. 0.92 preserves room for those externalities while signalling
that the chain itself is dense with evidence.

## Relationship to H1

H1 — MCP OAuth 2.0 Insecure Implementation — detects implementation
flaws (implicit flow, ROPC, redirect_uri injection, token storage). K6
detects scope breadth independent of flow: a PKCE-compliant OAuth 2.1
implementation with `scope: "admin"` fails K6 and passes H1. The two
rules are complementary and may both fire on the same server without
duplication.
