---
rule_id: C15
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: CWE-208
    url: https://cwe.mitre.org/data/definitions/208.html
    summary: >
      CWE-208 "Observable Timing Discrepancy". The canonical weakness
      class for non-constant-time secret comparison. The standard
      string equality operator (`===` / `==` in JS, `==` in Python)
      short-circuits on the first mismatched byte; the time-to-return
      leaks how many leading bytes matched. With enough samples an
      attacker reconstructs the secret one byte at a time.
  - kind: spec
    id: CWE-203
    url: https://cwe.mitre.org/data/definitions/203.html
    summary: >
      CWE-203 "Observable Discrepancy" — the parent class of CWE-208
      covering non-timing side channels too (cache, error message,
      length). The rule's structural analyser focuses on the timing
      sub-class because the source-only signal is unambiguous, but
      the broader weakness motivates the high severity.
  - kind: paper
    id: NodeJS-timingSafeEqual
    url: https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b
    summary: >
      Node.js `crypto.timingSafeEqual(a, b)` documentation. Explicitly
      states that `===` MUST NOT be used to compare secrets because
      "the comparison can be done in time depending on the data,
      which can leak information". This is the authoritative remediation
      target for the rule.
  - kind: paper
    id: Python-hmac-compare-digest
    url: https://docs.python.org/3/library/hmac.html#hmac.compare_digest
    summary: >
      Python `hmac.compare_digest(a, b)` — the Python equivalent. The
      docs are explicit: "This function uses an approach designed to
      prevent timing analysis by avoiding content-based short circuit
      behaviour".

lethal_edge_cases:
  - >
    `apiKey === req.headers.authorization` — direct triple-equals
    comparison between a server-side secret and a request-supplied
    value. The attacker iteratively refines the request value byte
    by byte and observes the response time.
  - >
    `token == provided_token` (Python) — equivalent in Python.
    `==` on byte strings or text strings short-circuits in CPython
    at the first mismatched byte. Same exploit profile as the JS
    case.
  - >
    `authHeader.startsWith(secret)` — startsWith is just as
    short-circuit-y as ===. A common "I'm not using ===" error.
  - >
    Naive HMAC byte-by-byte comparison loop — `for i in range(len(a)):
    if a[i] != b[i]: return False`. Even when the developer wrote a
    "constant-time" check, the early return makes it timing-vulnerable.
    The rule treats any `for` loop comparing two byte sequences with
    an early return as suspicious.
  - >
    Comparison via `String(a) === String(b)` or `Buffer.from(a) ===
    Buffer.from(b)` — coercion does not save the comparison; the
    underlying engine still short-circuits. The rule ignores the
    coercion wrapper and inspects the operator.

edge_case_strategies:
  - ast-strict-equality-on-secret    # === / == where one side is a secret-named identifier and the other is request-derived
  - ast-startswith-on-secret         # <secret>.startsWith(<request>) or <request>.startsWith(<secret>)
  - python-equality-on-secret        # Python `==` between secret-named identifier and request-derived value
  - timing-safe-import-suppression   # presence of crypto.timingSafeEqual / hmac.compare_digest in scope clears the finding
  - test-file-suppression            # AST-shape check rules out vitest/jest fixtures

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - ast_comparison_shape
    - secret_identifier_match
    - structural_test_file_guard
  location_kinds:
    - source

obsolescence:
  retire_when: >
    JavaScript and Python both ship a default `===` / `==` operator
    that is constant-time on byte sequences AND the MCP SDK enforces
    a `verifyToken` helper for every authentication flow. Until both
    halves exist, C15 retains high severity.
---

# C15 — Timing Attack on Secret or Token Comparison

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP servers in TypeScript, JavaScript, or Python whose
source files are available and which compare any kind of credential
against a request-supplied value.

## What an auditor accepts as evidence

A CWE-208 auditor accepts a structured chain showing:

1. **Source** — a source-kind Location naming the AST node where the
   timing-vulnerable comparison appears: a BinaryExpression with
   `===` / `==` whose operands are a secret-named identifier on one
   side and a request-derived expression on the other; or a
   PropertyAccessExpression for `.startsWith` / `.endsWith` between
   the same shapes.

2. **Sink** — the same Location: the comparison IS the side channel.
   The chain `sink_type` is `credential-exposure`.

3. **Mitigation** — recorded present/absent. "Present" means the
   surrounding source imports `crypto` (Node) and uses
   `crypto.timingSafeEqual(...)` OR imports `hmac` (Python) and
   uses `hmac.compare_digest(...)`.

4. **Impact** — `credential-theft`, scope `connected-services`. With
   ~1000 timing samples per byte and a 32-byte secret, the attacker
   recovers the full credential in seconds-to-minutes over the
   network.

5. **Verification steps** — one for the comparison shape, one for
   the timing-safe import search, one for the rate-limiting check
   (rate limit alone does not save you, but its absence makes the
   attack faster).

## Why confidence is capped at 0.90

The rule cannot resolve every alias / wrapper for the secret-named
identifier. The 0.10 gap is reserved for cases where the secret has
been renamed via destructuring or where the comparison happens
inside an imported helper function the static analyser does not
descend into.
