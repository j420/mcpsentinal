# Package: compliance-agents

**Purpose:** Adversarial Compliance Framework. Six framework-specific agents
(OWASP MCP, OWASP ASI, CoSAI, MAESTRO, EU AI Act, MITRE ATLAS) that scan an
MCP server through the lens of a compliance regime and produce per-framework
audit reports backed by dynamically generated adversarial tests.

This is the ONLY package allowed to call an LLM (ADR-009 exception). All
other packages remain deterministic per ADR-006.

## Hierarchy

```
FrameworkAgent
  └── Category (e.g. EU AI Act → "Article 14 — Human Oversight")
       └── ComplianceRule (shared OR framework-specific)
            └── ComplianceTest[]    ← synthesized at runtime per server
                 └── ComplianceFinding (with EvidenceChain + LLM rationale)
```

## Authoring Protocol — Dual Persona

Every `ComplianceRule` is authored under a documented protocol:

1. **Senior MCP Threat Researcher** writes `CHARTER.md` next to the rule.
   It states the threat model, real-world references (CVE, paper, incident),
   the lethal edge cases, and what evidence convinces a skeptical auditor.
2. **Senior MCP Security Engineer** translates the charter into a
   `ComplianceRule` subclass implementing:
   - `gatherEvidence(context)` — DETERMINISTIC. Reuses analyzer infra
     (`taint-ast`, `capability-graph`, `entropy`, `similarity`,
     `module-graph`, `schema-inference`). **No regex literals. No
     long string-array constants.**
   - `testStrategies()` — declares `EdgeCaseStrategy[]` for the runtime
     generator.
   - `judge(bundle, llmVerdict)` — DETERMINISTIC re-validation of the
     LLM's verdict against structural evidence. The LLM verdict is
     ignored unless `judge()` confirms it.

## The "no static, no regex" guarantee

Two CI guards enforce this mechanically:

- `__tests__/no-static-patterns.test.ts` — AST-scans every file under
  `src/rules/` and fails if any of the following appear:
  - A `RegExp` literal (`/.../`)
  - A `new RegExp(...)` call
  - A string-literal array constant longer than 5 entries
- `__tests__/charter-traceability.test.ts` — parses every `CHARTER.md`
  and asserts the rule id, threat refs, and edge-case strategies match
  the corresponding TypeScript file.

If you need to detect a pattern, do it via AST queries
(`tree-sitter` / TypeScript compiler API) or capability-graph traversal,
NOT via regex.

## How tests become "dynamic"

1. **Deterministic gather** → produces an `EvidenceBundle` (typed facts).
2. **LLM synthesis** → Claude reads the bundle + charter + control text
   and produces N adversarial test cases tailored to *this server's*
   actual surface. Edge-case strategies (`unicode-evasion`,
   `consent-bypass`, `audit-erasure`, etc.) constrain what the model
   can produce.
3. **LLM execution** → second LLM call evaluates each test against the
   bundle, returning a structured verdict.
4. **Deterministic judge** → re-validates the verdict. Only judge-confirmed
   verdicts become `ComplianceFinding`s.

The LLM never sees raw server source code on its own. It only sees the
deterministically gathered evidence bundle. This is the hallucination
firewall.

## LLM Audit Trail (mandatory)

Every LLM call is persisted to `compliance_agent_runs` with:
- prompt, response, model id, temperature, max_tokens
- rule id, server id, run id
- duration, token counts
- whether the response was cached

Auditors can replay any compliance scan by re-running the cached prompts.

## Confidence Cap

LLM-derived findings are capped at confidence 0.85 (vs 0.99 for purely
deterministic rules). The confidence layer in `src/llm/confidence.ts`
applies this cap and adds `analysis_technique: 'llm-reasoning'` factors
to the evidence chain.

## Isolation vs Combined Execution

```bash
# isolation — only one framework
pnpm compliance-scan --server=<id> --framework=eu_ai_act

# combined — all six frameworks share rule executions
pnpm compliance-scan --server=<id> --framework=all
```

In combined mode the orchestrator computes the union of rules across
requested frameworks, runs each rule once, and demultiplexes findings
into per-framework reports. Shared rules surface in every framework
report that references them.

## What NOT to do

- Do NOT add regex literals or long string constants in `src/rules/` —
  the no-static-patterns guard will fail CI.
- Do NOT call an LLM from outside `src/llm/` — only the LLM client
  module is allowed to instantiate the Anthropic SDK.
- Do NOT modify the existing 164 TypedRules in `packages/analyzer/` —
  this package is additive.
- Do NOT write findings to the existing `findings` table — use the
  new `compliance_findings` table.
- Do NOT skip the `judge()` step — it is the hallucination firewall.
