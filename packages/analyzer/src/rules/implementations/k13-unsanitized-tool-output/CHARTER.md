---
rule_id: K13
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: CoSAI-MCP-T4
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      Coalition for Secure AI MCP threat taxonomy T4 — Data / Control
      Boundary Failure. Tool outputs carrying untrusted external content
      straight to the AI client without sanitization are a direct T4
      violation: the client is entitled to assume tool responses were
      scrubbed at the server boundary.
  - kind: spec
    id: OWASP-ASI02
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: >
      OWASP Agentic Security Initiative ASI02 — Tool Misuse. Names
      unsanitized response data as an archetypal tool-misuse vector:
      the AI interprets the tool's response as a trustworthy statement
      of fact, granting external content authority it never earned.
  - kind: spec
    id: MAESTRO-L3
    url: https://cloudsecurityalliance.org/research/topics/multi-agent-threat-modeling
    summary: >
      MAESTRO Layer 3 (Communication) treats every inter-component
      message as untrusted until sanitized. The tool-to-AI response is
      an inter-component message. Skipping sanitization in that path
      violates L3 whether the content is executable or not — pure
      text injection carries the same control-plane threat as HTML.
  - kind: paper
    id: Rehberger-Indirect-Injection-2024
    url: https://embracethered.com/blog/
    summary: >
      Johann Rehberger demonstrated indirect prompt injection against
      Claude and GPT-4 via web-scraping MCPs that returned attacker-
      controlled page content verbatim. The output-side gap the
      attack exploits is exactly what K13 names.

lethal_edge_cases:
  - >
    External source reached via a receiver.method pair that is not in
    the vocabulary — e.g. `db.query(sql)` where `db` is a project-
    specific ORM wrapper. A detector keyed on `axios.get / fetch /
    readFile` misses it. The rule accepts ANY CallExpression whose
    callee name OR method name contains a token from a broad external-
    source vocabulary (fetch, read, query, scrape, get, download,
    request, find), and records it under a canonical source kind.
  - >
    Sanitizer applied to a different variable than the one returned —
    `const safe = sanitize(A); return B;`. A "sanitizer present in
    scope" check would false-negative K13. The rule checks whether
    the sanitizer argument is the SAME identifier that reaches the
    response, by tracking taint through simple variable assignments
    in the enclosing function body.
  - >
    Taint source is an inbound parameter of the handler, not a direct
    external call — e.g. `async function(data) { return data; }` where
    `data` was fetched upstream. The rule extends the taint source set
    to handler parameters whose NAMES contain external-content tokens
    (content, body, page, response, scraped, fetched, result, data,
    payload) and treats them as untrusted at the boundary.
  - >
    Response returned via awaited promise chain — `return (await
    fetch(...)).text()`. The tainted value lives inside a chained
    PropertyAccess / AwaitExpression; a simple "Identifier → return"
    check misses it. The rule walks the expression tree from the
    ReturnStatement / response-call argument and looks for ANY
    descendant CallExpression matching the external-source vocabulary.
  - >
    Test fixtures simulate an external source with a literal string —
    `return await fetch("...")` in a test file. Firing on these
    destroys signal. Structural test-file detection (vitest / jest /
    mocha import + describe/it/test top-level) skips the file whole.
    Filename-based skipping is explicitly avoided (K1 lesson).

edge_case_strategies:
  - external-source-vocabulary        # broad token-set for source classification
  - taint-tracked-sanitizer-check     # sanitizer argument must equal the returned identifier
  - handler-parameter-taint           # parameters whose names imply external content count as sources
  - descendant-expression-walk        # walk the response expression tree looking for tainted call
  - structural-test-file-detection    # skip test files by AST shape, not filename

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - external_source_kind
    - no_sanitizer_on_returned_value
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP clients sandbox every tool response payload and run it through
    a protocol-level sanitizer before rendering — at which point the
    server-side sanitization gap K13 names becomes a client control,
    and this rule's sink moves to a different layer.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
mutations_acknowledged_blind: []
---

# K13 — Unsanitized Tool Output

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP server handlers that return content sourced from
any external read (network fetch, filesystem, database, inter-tool
communication).

## What an auditor accepts as evidence

A CoSAI T4 auditor will not accept "there is no sanitizer call in
this file". They will accept a rule that:

1. Names the **external source** — a concrete CallExpression or a
   typed handler parameter with a `source`-kind Location — and
   classifies it (`network-fetch`, `file-read`, `db-query`,
   `handler-param`).

2. Names the **return path** the taint reaches — a ReturnStatement
   or a response-emitting call (`res.send`, `res.json`, `ctx.body`,
   `reply.send`) with a `source`-kind Location.

3. Reports the **sanitizer mitigation** against the returned value
   specifically — not against any variable in scope. A sanitizer
   applied to a different identifier is recorded as PRESENT with a
   caveat that requires manual applicability confirmation.

4. States the **impact** in concrete terms — the AI client processes
   the response as if it were a trustworthy tool output. Untrusted
   text reaching the model at the tool-output boundary is the
   indirect-injection archetype (Rehberger 2024, Invariant Labs 2025).

## Confidence cap — 0.90

The strongest proof is a full source→sink taint chain with a same-
variable sanitizer check. The engine can prove this within a single
function body. Cross-module sanitization (response goes through a
framework middleware) is not observable at file scope — the 0.90 cap
reflects that uncertainty.
