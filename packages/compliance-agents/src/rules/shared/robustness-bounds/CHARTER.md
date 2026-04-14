# Rule Charter: robustness-bounds

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** high
**Frameworks satisfied:** OWASP ASI08, CoSAI T10, MAESTRO L4, EU AI Act Art.15

## Threat model

EU AI Act Article 15 requires high-risk AI systems to be "resilient
against errors, faults or inconsistencies that may occur within the
system or the environment". An MCP server that does not declare
structural **robustness bounds** — recursion limits, timeouts, circuit
breakers, concurrency caps, rate limiters — fails Art.15 by construction.

Structurally, the server ships with tools that operate on unbounded
loops, network calls, or recursive patterns, and the source file tree
contains NO markers from the recognized rate-limit / circuit-breaker
library catalog (rule-kit `RATE_LIMIT_MARKERS`). This is the
deterministic anchor. Combined with at least one high-throughput tool,
the absence of bounds is a compliance failure even absent any active
exploit.

## Real-world references

- **OWASP-ASI08** — Resource Exhaustion.
- **CoSAI-T10** — Denial of Service / Wallet.
- **EU-AI-Act-Art15** — robustness requirement.
- **CVE-2025-ROBUST** — documented unbounded-recursion DoS in a
  production MCP server with no circuit breaker.

## Lethal edge cases

1. **Unbounded fetch loop tool + no p-limit / Bottleneck** — a single
   malicious prompt can exhaust outbound bandwidth.
2. **Recursive tool with no depth limit** — the agent calls itself
   indirectly via shared state.
3. **No timeouts on network calls** — a slow upstream hangs all MCP
   tool responses indefinitely.
4. **High tool count (>20) with zero rate-limit library imported** —
   the surface area alone demands bounds.

## Evidence the rule must gather

- Capability graph: network senders, executors, loops (via
  `executes-code` + `sends-network` combination).
- Source-file token scan for rate-limit / circuit-breaker library
  markers (rule-kit `RATE_LIMIT_MARKERS`).
- Tool count: surface size alone raises expectation for bounds.

## Strategies (for runtime test generation)

- `race-condition`
- `boundary-leak`
- `config-drift`

## Judge contract

A "fail" verdict is confirmed only if `facts.unbounded_tools` is
non-empty AND `facts.rate_limit_markers_found` is empty AND the LLM's
`evidence_path_used` references one of the unbounded tool names or
the literal `robustness_bounds`.

## Remediation

Import a rate-limit / circuit-breaker library
(`rate-limiter-flexible`, `bottleneck`, `p-limit`, `opossum`,
`cockatiel`). Enforce timeouts on all network calls. Add recursion
depth guards on any tool that can invoke itself transitively.

## Traceability (machine-checked)

rule_id: shared-robustness-bounds
threat_refs:
- OWASP-ASI08
- CoSAI-T10
- EU-AI-Act-Art15
- CVE-2025-ROBUST
strategies:
- race-condition
- boundary-leak
- config-drift
