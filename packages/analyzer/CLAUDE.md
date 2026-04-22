# Package: analyzer

**Purpose:** Load detection rules from YAML and run them against an `AnalysisContext`. The most complex package — the rules engine.

## Key Files
- `src/engine.ts` — `AnalysisEngine` class + `AnalysisContext` type
- `src/rule-loader.ts` — `loadRules()`, `getRulesVersion()`
- `src/__tests__/engine.test.ts` — rule engine tests

## AnalysisContext Shape

```typescript
interface AnalysisContext {
  server: { id, name, description, github_url }
  tools: Array<{ name, description, input_schema }>
  source_code: string | null          // concatenated GitHub source files
  dependencies: Array<{               // from DependencyAuditor
    name, version, has_known_cve, cve_ids, last_updated
  }>
  connection_metadata: {              // null if no live connection
    auth_required: boolean
    transport: string
    response_time_ms: number
  } | null
  initialize_metadata?: {             // H2 surface — populated from MCPConnector.enumerate()
    server_version?: string | null
    server_instructions?: string | null
  }
}
```

## Detection Architecture: Single-Path Dispatch

All 164 active rules are `TypedRuleV2` implementations with mandatory `EvidenceChain` (13 retired). Zero YAML regex patterns remain. There is no YAML fallback: the legacy `runRegexRule`, `runSchemaCheckRule`, `runBehavioralRule`, and `runCompositeRule` dispatchers — along with the v1 `TypedRule` interface and `V1RuleAdapter` — were deleted in Phase 1 chunk 1.28.

Detection now runs through two complementary dispatch paths:

**(a) Five specialized engines in `src/engines/`** — for categories where cross-rule shared infrastructure is economical:
- **CodeAnalyzer** — C1–C16 (AST taint, secrets, entropy)
- **DescriptionAnalyzer** — A1–A9 (linguistic injection scoring, Unicode, encoding)
- **SchemaAnalyzer** — B1–B7 (structural inference)
- **DependencyAnalyzer** — D1–D7 (similarity, CVE lookup)
- **ProtocolAnalyzer** — I1–I16, J1, J5 (transport, OAuth, annotations)

**(b) `TypedRuleV2` classes in `src/rules/implementations/<rule-id>/`** — one directory per rule, conforming to the Rule Standard v2 contract (CHARTER.md + gather.ts + verification.ts + index.ts + data/ + __fixtures__/ + __tests__/index.test.ts). Rules self-register via `registerTypedRuleV2` at module load.

YAML declares metadata only (`detect.type: typed`). Rules previously dispatched via the YAML fallback have all been migrated — the four dispatchers have been removed and the `detect.type` values `regex` / `schema-check` / `behavioral` / `composite` are no longer honored anywhere.

**Adding a new rule**: Follow the Rule Standard v2 briefing template in `agent_docs/sub-agent-orchestration.md`. Reference implementation: `src/rules/implementations/k1-absent-structured-logging/`. See also `rules/CLAUDE.md`.

## Analyzer Context

The context → text mapping helper (`getTextsForContext`) was removed alongside `runRegexRule` in chunk 1.28. `TypedRuleV2` rules read directly from the structured `AnalysisContext` — for example, `context.tools[i].description`, `context.tools[i].input_schema`, `context.source_code`, `context.initialize_metadata?.server_instructions`, etc. The former `context` YAML field is no longer interpreted.

The H2 rule surface lives in `AnalysisContext.initialize_metadata` (`server_version` + `server_instructions`), populated from `MCPConnector.enumerate()` via `client.getServerVersion()` + `client.getInstructions()`.

## Every Finding Must Have
```typescript
{
  rule_id: string,                  // e.g., "C1"
  severity: Severity,               // critical | high | medium | low | informational
  evidence: string,                 // narrative rendered from the EvidenceChain
  remediation: string,              // HOW to fix it — from the rule YAML
  owasp_category?: string,
  mitre_technique?: string,
  confidence: number,               // 0.0–1.0, capped at 0.85 for LLM-derived findings (ADR-009)
  metadata: { evidence_chain: EvidenceChain }  // source → propagation* → sink → mitigation → impact
}
```
`EvidenceChain` is mandatory. A finding without an evidence chain is a bug — the `charter-traceability` CI guard will fail the build. The `evidence` string must be rendered from the chain, not authored ad-hoc.

## Running Tests
```bash
pnpm test --filter=analyzer
pnpm test --filter=analyzer --watch   # during development
```

## What NOT to Do
- Do NOT add LLM API calls — all analysis is deterministic (ADR-006)
- Do NOT add inline SQL — no DB access in this package
- Do NOT discard findings because you don't have a rule for the pattern — collect everything
- Do NOT change `AnalysisContext` shape without updating `packages/scanner/src/pipeline.ts`
