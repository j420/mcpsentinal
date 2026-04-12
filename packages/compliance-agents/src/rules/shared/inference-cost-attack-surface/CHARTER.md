# Rule Charter: inference-cost-attack-surface

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** medium
**Frameworks satisfied:** OWASP ASI08, CoSAI T10, MAESTRO L4, EU AI Act Art.15

## Threat model

Where robustness-bounds targets general resource exhaustion, this rule
targets the **LLM-specific** cost-attack surface: tools that trigger
inference requests (sampling, large-context returns, recursive prompts,
embedding lookups) without structural cost caps in source
(`max_tokens`, `token_budget`, `inferenceQuota`, etc. — rule-kit
`COST_CAP_MARKERS`).

Unlike the sampling-capability-safety rule, which targets the
injection-amplification loop, this one targets the pure **denial-of-
wallet** pattern: a server whose design allows a single call to
trigger unbounded inference spend on the client side, even without
ingestion or prompt injection.

## Real-world references

- **CVE-2025-WALLET** — "Denial-of-wallet attack on MCP sampling
  client"; single malicious call drove $10k of inference spend in
  four hours.
- **OWASP-ASI08** — Resource Exhaustion.
- **MCP-Spec-2025-06-18** — sampling capability introduced without a
  cost-cap contract.

## Lethal edge cases

1. **Sampling capability + no cost caps + no timeouts** — single
   invocation triggers unbounded spend.
2. **Huge context-returning tool** (e.g. "return entire repo as
   inference context") with no pagination.
3. **Recursive planner tool** that re-invokes itself via an agent
   loop with no depth cap.

## Evidence the rule must gather

- Source-file token scan for cost-cap markers (rule-kit
  `COST_CAP_MARKERS`).
- Capability-graph scan: tools with `executes-code` or that declare
  sampling via `declared_capabilities.sampling`.
- Presence of at least one executor tool AND absence of cost caps AND
  sampling declaration is the deterministic violation.

## Strategies (for runtime test generation)

- `race-condition`
- `boundary-leak`
- `cross-tool-flow`

## Judge contract

A "fail" verdict is confirmed only if `facts.cost_caps_found` is empty
AND `facts.inference_sinks` is non-empty AND the LLM's
`evidence_path_used` references one of the inference sink tool names
or the literal `inference_cost`.

## Remediation

Add structured cost caps to the sampling path (`max_tokens`,
`token_budget`, `inferenceQuota`). Set timeouts on every inference
call. Cap recursion depth on planner-style tools. Prefer streaming
with early-abort semantics over unbounded context returns.

## Traceability (machine-checked)

rule_id: shared-inference-cost-attack-surface
threat_refs:
- CVE-2025-WALLET
- OWASP-ASI08
- MCP-Spec-2025-06-18
strategies:
- race-condition
- boundary-leak
- cross-tool-flow
