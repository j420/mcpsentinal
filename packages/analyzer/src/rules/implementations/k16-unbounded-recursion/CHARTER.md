---
rule_id: K16
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: OWASP-ASI08
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: >
      OWASP Agentic Security Initiative Top 10, ASI08 — Denial of Service.
      Names unbounded recursion as an archetypal cascading-failure enabler in
      agentic systems: a single unguarded self-invoking function consumes stack
      or re-enters the tool-call boundary until the process dies. Agentic
      runtimes amplify the risk because tool-call chains give the LLM a
      cheap way to drive a recursion to its limit.
  - kind: spec
    id: EU-AI-Act-Art-15
    url: https://eur-lex.europa.eu/eli/reg/2024/1689/oj
    summary: >
      EU AI Act Article 15 — Accuracy, robustness and cybersecurity. Requires
      high-risk AI systems to be resilient to errors, faults, and malicious
      inputs. A tool handler whose recursive branch has no depth counter,
      bounded guard, or cycle breaker defeats the robustness requirement:
      adversarial input deterministically drives the handler to a stack
      overflow / RSS blow-out / tool-call storm.
  - kind: spec
    id: CoSAI-MCP-T10
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      CoSAI MCP threat taxonomy T10 — Resource Exhaustion. Unguarded recursion
      is called out as a first-class exhaustion primitive. The taxonomy names
      the MCP-specific variant: a tool that invokes another tool which, under
      attacker control, invokes the original tool — a cross-boundary cycle
      that a per-function static guard alone does not prevent.
  - kind: spec
    id: MAESTRO-L4
    url: https://cloudsecurityalliance.org/research/topics/multi-agent-threat-modeling
    summary: >
      MAESTRO Layer 4 (Deployment & Infrastructure) requires circuit breakers
      and bounded concurrency on every in-process compute primitive. An
      unbounded recursive handler violates L4 at the source level regardless
      of process-level cgroup / ulimit protections, because a single agent
      invocation can consume the entire per-process quota before any external
      breaker fires.
  - kind: cve
    id: CVE-2025-6514
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-6514
    summary: >
      mcp-remote command injection (CVSS 9.6) — the CVE itself is about
      command injection, but the weaponised proof-of-concept chains it with
      recursion-driven amplification inside the MCP client's retry/
      reconnect loop. K16's tool-call-cycle case is the static companion to
      that runtime pattern.

lethal_edge_cases:
  - >
    Mutual recursion across two handlers: `handlerA` calls `handlerB`, which
    calls `handlerA`. Neither function calls itself directly, so a
    self-call scan misses the cycle entirely. The rule builds a call graph
    and computes strongly-connected components; any SCC with more than one
    node is a mutual-recursion cycle and fires even when individual
    functions have no self-call.
  - >
    Attacker-controlled guard: `function walk(node, depth = req.body.depth)
    { if (!node) return; walk(node.next, depth + 1); }`. The function
    declares a `depth` parameter — a naive depth-guard check would accept
    it — but the parameter default is sourced from untrusted input and the
    body contains no comparison against an upper bound. The rule requires
    the function body to contain an actual comparison (BinaryExpression)
    between the guard parameter and either a numeric literal or an
    UPPER_SNAKE constant. A mere parameter name is not a guard.
  - >
    Indirect recursion via event emitter: `emitter.on('x', handle); function
    handle() { emitter.emit('x'); }`. The function does not textually call
    itself, but emitting triggers the registered listener which calls the
    function again. The rule treats an `emit(...)` / `dispatch(...)` / MCP
    tool-call where the emitted event name / tool name equals the
    enclosing handler's own identifier or tool-registration name as a
    recursion edge — same SCC.
  - >
    Tool-call roundtrip cycle (MCP-specific): handler `readContext` calls
    `server.callTool("summarize")`, and `summarize` calls
    `server.callTool("readContext")`. Each individual function looks clean.
    The rule treats any `<receiver>.call(...)` / `.invoke(...)` / `.callTool(...)`
    whose first argument is a string literal as a synthetic edge from the
    enclosing function to a node labelled by that string. If the target
    string matches another function's identifier or a registered tool
    name in the same file, the edge joins them in the call graph and
    the SCC check fires.
  - >
    Queue / work-list re-enqueue: `function step() { while (queue.length) {
    const item = queue.pop(); process(item); } } function process(item) {
    queue.push(derive(item)); step(); }`. The work-list is not visible to a
    purely structural call graph, so the rule treats a function that both
    invokes another function AND writes to a shared identifier that the
    other function reads in an unbounded loop as a SUSPECTED cycle. This
    is an acknowledged false-negative window — the rule does NOT fire
    for untyped queue recursion unless one of the other edge types also
    fires. Flagged in the charter.
  - >
    Guard exists but operates on the WRONG variable: the function accepts a
    `depth` parameter, passes `depth + 1` to the recursive call, but checks
    `if (otherVar > MAX_DEPTH)` — the guard never binds. Static detection
    is structurally correct (a comparison exists, an upper-bound constant
    is compared) but the guard is vacuous. Acknowledged false-negative
    window; the reviewer inspects the connection.

edge_case_strategies:
  - call-graph-scc-detection        # direct + mutual + tool-call + emit
  - depth-guard-comparison-check    # BinaryExpression: param vs numeric / UPPER_SNAKE
  - cycle-breaker-visited-set       # Set/Map/WeakSet seen near recursive call
  - structural-test-file-detection  # vitest/jest/mocha imports + top-level it/test
  - tool-call-cycle-synthesis       # receiver.call("X") → node X in graph
  - event-emitter-cycle-synthesis   # emit("handle") re-enters handler

evidence_contract:
  minimum_chain:
    source: true
    propagation: true        # the recursion edge flows to a re-invocation
    sink: true
    mitigation: true         # depth guard / cycle breaker — present or absent
    impact: true
  required_factors:
    - recursion_edge_without_guard
    - no_depth_parameter | no_depth_comparison | no_cycle_breaker
  location_kinds:
    - source

obsolescence:
  retire_when: >
    The Node.js / V8 runtime grows a first-class, on-by-default recursion
    budget for every async function AND the MCP protocol gains a
    spec-level tool-call-depth limit that all compliant clients enforce
    (today Anthropic Desktop, Cursor, and Claude Code all lack one).
    Neither direction is on a published roadmap; the rule is expected
    to remain load-bearing through 2027.
---

# K16 — Unbounded Recursion / Missing Depth Limits

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP server source code whose tool handlers, helpers, or
request dispatchers use recursive patterns — direct, mutual, event-
driven, or tool-call roundtrip — without an observable guard.

## What an auditor accepts as evidence

An OWASP ASI08 / EU AI Act Art.15 auditor will not accept "this function
name appears in its own body". They will accept a chain that cites, at
minimum:

1. **Call-graph proof** — the finding cites a `source` Location at the
   exact line:column of a CallExpression that closes a recursion cycle,
   identified by strongly-connected-component analysis over all
   FunctionDeclarations / MethodDeclarations / variable-bound
   FunctionExpressions / ArrowFunctions in the file. Direct self-calls,
   mutual recursion, and synthesised tool-call / emit edges all
   participate in the same graph.

2. **Guard proof** — the finding states whether the cycle's entry
   function declares a parameter in `DEPTH_PARAMETER_NAMES` AND whether
   the function body contains a BinaryExpression comparing that parameter
   to a numeric literal or an UPPER_SNAKE constant. Presence of the
   parameter alone is NOT a guard — the comparison is the guard.

3. **Cycle-breaker proof** — the finding states whether the enclosing
   scope contains a Set / Map / WeakSet / WeakMap instantiation with a
   subsequent `.has(...)` or `.add(...)` call reachable from the
   recursive call. A visited-set dampens cycles even when no depth
   parameter is present.

4. **Test-file proof** — the finding records whether the enclosing
   source file was classified as a test file by two-signal structural
   detection (vitest/jest/mocha runner import + top-level `it` / `test`
   call). Recursive helpers in test fixtures are NOT flagged; the
   reviewer sees the classification in the verification step.

## What the rule does NOT claim

- It does not resolve cross-file call graphs. A tool handler in
  `./handlers/a.ts` that calls a tool registered in `./handlers/b.ts`
  produces a cycle only when both files are in the analysis context's
  `source_files` map and scanned together. Single-file scans miss
  inter-file cycles. Phase 2 cross-file resolution addresses this.
- It does not prove the guard is bound to the specific recursive call
  path. A function with a depth comparison on `otherVar` while passing
  `depth + 1` into the recursion is an acknowledged false-negative
  window (charter edge case 6).
- It does not observe runtime-level mitigations: Node.js
  `--stack-size`, Node.js 22 async-stack-budget proposals, OS cgroup
  memory limits, MCP client-side tool-call-depth limits.

## Why confidence is capped at 0.88

Static analysis cannot observe:

- process-level stack-size overrides (`node --stack-size=...`);
- MCP client-side per-session tool-call-depth enforcement
  (Anthropic Desktop / Cursor / Claude Code all implement this
  differently and none expose it in protocol metadata);
- runtime circuit breakers that wrap the handler externally (opossum,
  cockatiel) — the library presence is a dependency signal, not a
  binding guarantee.

A maximum-confidence claim would overstate what the static evidence
proves. 0.88 preserves room for those externalities while the chain
itself is dense with AST evidence.

## Relationship to K17 and C11

- **K17 (Missing Timeout)** bounds HTTP-bound hangs; K16 bounds
  in-process recursion. A well-configured server passes both.
- **C11 (ReDoS)** bounds regex-driven catastrophic backtracking; the
  attacker payload is a string. K16 bounds call-level recursion; the
  attacker payload is a data structure depth or a tool-call target
  sequence. Same DoS class, different primitive.
