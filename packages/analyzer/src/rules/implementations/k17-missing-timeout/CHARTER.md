---
rule_id: K17
interface_version: v2
severity: medium

threat_refs:
  - kind: spec
    id: OWASP-ASI08
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: >
      OWASP Agentic Security Initiative Top 10, ASI08 — Denial of Service.
      An MCP tool handler that awaits an HTTP call with no timeout will
      occupy its worker slot until the upstream responds or the OS-level
      TCP timer fires (often minutes). With concurrent tool calls this
      becomes a self-inflicted DoS, independent of any attacker.
  - kind: spec
    id: EU-AI-Act-Art-15
    url: https://eur-lex.europa.eu/eli/reg/2024/1689/oj
    summary: >
      EU AI Act Article 15 — Accuracy, robustness and cybersecurity. Requires
      that high-risk AI systems be resilient to errors, faults, and malicious
      inputs. A hanging HTTP call in an agentic tool handler defeats the
      robustness requirement: the system neither recovers nor sheds load.
  - kind: spec
    id: MAESTRO-L4
    url: https://cloudsecurityalliance.org/research/topics/multi-agent-threat-modeling
    summary: >
      MAESTRO Layer 4 (Deployment & Infrastructure) requires timeouts and
      circuit breakers on every outbound dependency. A tool implementation
      without timeouts lives inside a deployment that cannot satisfy L4
      regardless of infrastructure.
  - kind: spec
    id: CoSAI-MCP-T10
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      CoSAI MCP threat taxonomy T10 — Resource Exhaustion. Missing
      application-level timeouts are the archetype: a small number of
      attacker-induced slow-loris responses are sufficient to starve the
      server of connection-pool capacity.

lethal_edge_cases:
  - >
    Per-call timeout set via a variable: `const opts = { timeout: 5000 };
    axios.get(url, opts)`. The argument is an Identifier, not an
    ObjectLiteralExpression. Static detection without cross-scope
    resolution misses this. The rule ACKNOWLEDGES this false-positive
    window: the enclosing-scope walker picks up AbortSignals in the same
    block but does NOT resolve generic options-object variables.
  - >
    Global axios defaults set in a sibling module that's imported for
    side-effects (`import "./setup-axios";`). The sibling file contains
    `axios.defaults.timeout = 5000`. The rule's global-timeout scan
    operates per-file; sibling imports are NOT resolved. Charter records
    this as an acknowledged false-positive window; Phase 2 cross-file
    resolution addresses it.
  - >
    `AbortSignal.timeout(5000)` used inline: `fetch(url, { signal:
    AbortSignal.timeout(5000) })`. This IS picked up — the signal
    property is in CALL_TIMEOUT_OPTIONS. The detector treats any
    `signal` property as a mitigation regardless of its RHS value, to
    avoid matching the value expression.
  - >
    An enclosing scope declares `new AbortController()` but the signal
    is never passed to the fetch call. The rule uses a two-signal check
    (constructor + `.signal` reference) but does NOT confirm the signal
    is attached to THIS specific call. Acknowledged false-negative
    window; reviewers inspect the connection.
  - >
    `http.get(url, callback)` with a callback-style API. The options
    argument is optional and often omitted. Detection still fires —
    callback-style code has the same DoS characteristics as
    Promise-style. The verification step directs the reviewer to the
    `.setTimeout(ms)` method on the returned ClientRequest if it's used
    downstream.
  - >
    A circuit-breaker wraps the call externally: `breaker.fire(() => fetch(url))`.
    The wrapper injects a timeout that the static analyzer cannot see.
    The rule still fires on the bare fetch call inside the wrapper but
    applies the `circuit_breaker_dep_present` NEGATIVE factor when the
    project has one installed.

edge_case_strategies:
  - bare-and-receiver-http-call        # fetch vs axios.get, both recognised
  - options-object-timeout-check       # scan args for any timeout-option property
  - abort-signal-scope-walk            # ctor + .signal reference in enclosing scope
  - per-receiver-global-timeout        # axios.defaults / got.extend / ky.create
  - circuit-breaker-dep-as-mitigation  # opossum/cockatiel/brakes detected via deps
  - structural-test-file-detection     # two-signal (runner import + top-level call)

evidence_contract:
  minimum_chain:
    source: true
    propagation: true          # the HTTP call flows to outbound network
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - ast_http_call_without_timeout
    - no_circuit_breaker_dep | circuit_breaker_dep_present | global_timeout_present_different_client
  location_kinds:
    - source
    - dependency               # circuit-breaker mitigation
    - config                   # absence location (package.json/dependencies)

obsolescence:
  retire_when: >
    Every major HTTP client library ships a default (non-zero) timeout
    value at the library layer (fetch grows a spec-level default,
    axios/got/ky already do or will) AND the MCP runtime enforces a
    process-level request timeout — or OWASP ASI08 / EU AI Act Art.15
    adopt a post-hoc observability model that accepts runtime hangs
    provided they are surfaced. Neither direction is current.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
mutations_acknowledged_blind: []
---

# K17 — Missing Timeout or Circuit Breaker

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP server source code that issues HTTP / network
requests via any of the major Node.js client libraries.

## What an auditor accepts as evidence

An OWASP ASI08 auditor will not accept a rule that says "fetch
appears on a line". They will accept a rule that says:

1. **Call-site proof** — the finding cites a `source` Location at the
   exact line:column of a CallExpression whose callee is classified
   as an HTTP client by two-layer match (bare call OR receiver.method
   pair against curated vocabulary).

2. **Argument proof** — the finding states that the call's argument
   list was inspected for every timeout-shaped property name
   (timeout, signal, deadline, headersTimeout, bodyTimeout,
   requestTimeout, responseTimeout, connectTimeout) and none was
   found.

3. **Scope proof** — the finding states that the enclosing
   function/source-file scope was inspected for a two-signal pattern
   (AbortController constructor OR AbortSignal.timeout() + a
   `.signal` reference) and none was found.

4. **Global-timeout proof** — the finding states whether the file as
   a whole carries a receiver-matched global timeout
   (axios.defaults.timeout, got.extend, ky.create with timeout) and
   whether it covers THIS specific client.

5. **Dependency proof** — the finding records whether the project has
   a circuit-breaker library installed and names it when present.

## What the rule does NOT claim

- It does not resolve cross-file globals. A sibling module
  `./setup-axios.ts` that sets `axios.defaults.timeout` is invisible.
- It does not resolve variable-referenced options objects. Passing
  `axios.get(url, opts)` where `opts` is a variable bound earlier
  yields a finding; the step output directs the reviewer to trace
  `opts`.
- It does not confirm that a circuit-breaker wraps the call. Dependency
  presence is a CONFIDENCE signal, not a mitigation.

## Why confidence is capped at 0.88

Static analysis cannot observe:

- OS-level TCP connect timeouts that bound the socket independently;
- reverse-proxy / sidecar timeouts (Envoy, nginx, Istio);
- library-default timeouts introduced by the upstream maintainer
  without a code change in the server repo.

A maximum-confidence claim would overstate what is provable. 0.88
preserves room for those externalities. The chain itself is dense
with AST evidence.

## Relationship to E3

E3 (Response Time Anomaly) is a BEHAVIORAL rule that fires when a live
connection exceeds 10s. K17 is the STATIC counterpart: it fires on
the code that can produce such hangs. A well-configured server
passes both.
