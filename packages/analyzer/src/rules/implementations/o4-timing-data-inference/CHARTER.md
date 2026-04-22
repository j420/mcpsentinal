---
rule_id: O4
interface_version: "2.0"
severity: high

threat_refs:
  - kind: technique
    id: MITRE-ATLAS-AML.T0057
    url: https://atlas.mitre.org/techniques/AML.T0057
    summary: >
      MITRE ATLAS AML.T0057 (LLM data leakage). Timing side channels
      leak data through response time variation — the model or the
      client can observe the delta and infer secrets without the data
      ever entering the explicit output.
  - kind: paper
    id: MAESTRO-L2
    url: https://cloudsecurityalliance.org/research/topics/multi-agent-threat-modeling
    summary: >
      MAESTRO Layer 2 (Data) mandates that data-dependent control
      flow must not produce observable side effects. Conditional
      delays satisfy the classic timing-attack primitive and violate
      Layer 2 by construction.

lethal_edge_cases:
  - >
    Test-file camouflage — a file named src/foo.test.ts that is
    actually wired into the production handler via package.json.
    The rule must recognise test-file structure (describe/it/vitest
    imports) rather than rely on filename heuristics.
  - >
    Indirect condition — the conditional compares `hmac(input)` to
    `hmac(secret)`. Neither variable is literally named "secret" or
    "password"; the rule must also accept identifier names like
    "hash", "digest", "match" as data-dependent evidence.
  - >
    Mitigated by jitter — Math.random() * 100 is added to the delay
    value. The AST walker must recognise this additive-jitter pattern
    (BinaryExpression whose one side is a Math.random call) and
    suppress the finding.
  - >
    Constant-time library — crypto.timingSafeEqual or Python
    hmac.compare_digest imported but only used in one code path while
    another path still branches on the comparison result. The rule
    must check whether the timing-safe call is adjacent to the
    flagged conditional, not just present in the file.
  - >
    Comment-only delay — setTimeout(noop, 100) inside a commented-out
    code block. The AST pass parses the file and only visits live
    nodes; comments are not visited.

edge_case_strategies:
  - ast-test-nature-detection
  - expanded-sensitive-identifier-list
  - additive-jitter-recognition
  - adjacency-based-mitigation
  - comments-skipped-structurally

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - delay_in_conditional
    - no_timing_safe
  location_kinds:
    - source

confidence_cap: 0.85

obsolescence:
  retire_when: >
    MCP servers are required by the spec to emit a response time
    budget and each tool has a server-enforced constant timer that
    flushes the response regardless of internal branching.
---

# O4 — Timing-Based Data Inference

Detects delay / sleep / setTimeout calls inside data-dependent conditionals
with no constant-time mitigation in scope. AST-based; no regex. Confidence
capped at 0.85 because static reasoning cannot prove the actual delay
magnitude is observable by an attacker.
