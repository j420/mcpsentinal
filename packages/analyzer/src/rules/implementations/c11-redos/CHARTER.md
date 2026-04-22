---
rule_id: C11
interface_version: v2
severity: high

threat_refs:
  - kind: cve
    id: CVE-2017-16116
    url: https://nvd.nist.gov/vuln/detail/CVE-2017-16116
    summary: >
      `ms` package ReDoS — the parsing regex matched any digit prefix
      then a unit name, with a backtracking pattern that hung on long
      hostile inputs. Canonical npm-ecosystem ReDoS. Cited because the
      detector targets the same alternation+quantifier shape.
  - kind: cve
    id: CVE-2018-3721
    url: https://nvd.nist.gov/vuln/detail/CVE-2018-3721
    summary: >
      `lodash` ReDoS / prototype-pollution chain — the prototype-
      pollution part is C10's domain; the regex shape that enabled
      the lookup-key parsing failure exposed the same alternation +
      quantifier antipattern this rule targets in `_.template` and
      `_.set` path parsers.
  - kind: cve
    id: CVE-2024-52798
    url: https://nvd.nist.gov/vuln/detail/CVE-2024-52798
    summary: >
      `path-to-regexp` ReDoS. Used by express, fastify, koa-router. A
      crafted route pattern hangs the route matcher for tens of
      seconds on a single CPU. The MCP threat model applies directly
      because Streamable-HTTP MCP servers use these routers.
  - kind: spec
    id: CWE-1333
    url: https://cwe.mitre.org/data/definitions/1333.html
    summary: >
      CWE-1333 "Inefficient Regular Expression Complexity". The
      canonical weakness for catastrophic-backtracking regexes —
      `(a+)+`, `(a|a)+`, `(.*)*`, `^(a|aa)+$`. The rule's pattern
      analyser targets exactly these shapes.
  - kind: paper
    id: OWASP-ReDoS
    url: https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
    summary: >
      OWASP ReDoS overview. Lists the same antipatterns the rule
      detects (nested quantifiers, alternation overlap, polynomial
      blow-up) and the same remediations the rule recommends (re2 /
      bounded inputs / lookahead-free patterns).

lethal_edge_cases:
  - >
    `new RegExp(userInput)` — the user controls the pattern itself.
    Even a static analyser cannot prove the pattern is safe; the
    rule fires on any RegExp constructor whose first argument is not
    a string literal.
  - >
    Nested quantifier — `(a+)+`, `([0-9]+)+`, `(\d+)+`. The inner
    `+` lets the engine match the inner group against the same input
    in many ways; the outer `+` multiplies that ambiguity. Hangs on
    inputs of the form "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
    (a long run of the matching char terminated by a non-match).
  - >
    Alternation overlap — `(a|a)+`, `(a|ab)+`, `(.|a)+`. The two
    branches match the same input; the engine tries every
    combination on backtracking. Hangs the same way as the nested
    quantifier case.
  - >
    `(.*)*` / `(.+)+` — the explicit polynomial-blow-up case.
    Listed in the OWASP ReDoS guide as the canonical example.
  - >
    Catastrophic backtracking inside route matcher — a path-to-regexp-
    style route expression that compiles to one of the above shapes.
    The user supplies the path via the URL; the route matcher runs
    on every request. The rule does not attempt to walk through
    path-to-regexp; instead it flags the underlying RegExp pattern
    when one appears literally.

edge_case_strategies:
  - ast-regexp-literal-pattern     # walk RegularExpressionLiteral and parse the pattern
  - ast-new-regexp-non-literal     # `new RegExp(<expr>)` where <expr> is not a string literal
  - structural-pattern-analyser    # hand-coded scanner for nested quantifiers + alternation overlap
  - bounded-input-suppression      # presence of a length cap before regex use suppresses fire
  - test-file-suppression          # AST-shape check rules out vitest/jest fixtures

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - ast_regex_pattern
    - regex_complexity_kind
    - structural_test_file_guard
  location_kinds:
    - source

obsolescence:
  retire_when: >
    The Node.js / Python / Deno default regex engines all switch to
    a linear-time engine (re2 / Hyperscan), so catastrophic
    backtracking is impossible by construction — AND the V8
    `--no-experimental-fetch`-style flag for "safe regex only" is
    on by default. Until both halves exist, C11 retains high severity.
---

# C11 — ReDoS — Catastrophic Regex Backtracking

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP servers in TypeScript, JavaScript, or Python whose
source files are available and which compile or use regular
expressions.

## What an auditor accepts as evidence

A CWE-1333 / OWASP ReDoS auditor accepts a structured chain showing:

1. **Source** — a source-kind Location naming the AST node where the
   dangerous regex appears: a `RegularExpressionLiteral` whose
   pattern text matches the structural antipatterns OR a `new
   RegExp(<expr>)` whose argument is not a string literal.

2. **Sink** — the same Location: the regex compilation IS the
   dangerous operation. The chain `sink_type` is `code-evaluation`
   (the regex engine evaluates user-controllable structure).

3. **Mitigation** — recorded present/absent. "Present" means the
   surrounding code uses `re2` / `node-re2` / `RE2` (linear-time
   engine) OR clamps the input length before regex use.

4. **Impact** — `denial-of-service`, scope `server-host`. A single
   crafted input pegs one CPU for seconds-to-minutes; for an MCP
   server with no per-request timeout this stalls every concurrent
   tool invocation.

5. **Verification steps** — one for the regex shape, one for the
   bounded-input check, one for the engine swap.

## Why confidence is capped at 0.85

The structural pattern analyser is conservative and can miss
sophisticated antipatterns (lookahead-driven blow-ups, possessive-
quantifier-emulation tricks). The 0.15 gap is reserved for those.
