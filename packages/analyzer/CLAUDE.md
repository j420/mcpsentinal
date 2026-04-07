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

## Detection Architecture: 2-Phase Analysis

All 164 active rules are TypedRule implementations (13 retired). Zero YAML regex patterns remain.

### Phase 1: Specialized Engines + TypedRules (all detection logic)
Five specialized engines in `src/engines/` run first, then self-registering TypedRules in `src/rules/implementations/` cover the rest:
- **CodeAnalyzer** — C1–C16 (AST taint, secrets, entropy)
- **DescriptionAnalyzer** — A1–A9 (linguistic injection scoring, Unicode, encoding)
- **SchemaAnalyzer** — B1–B7 (structural inference)
- **DependencyAnalyzer** — D1–D7 (similarity, CVE lookup)
- **ProtocolAnalyzer** — I1–I16, J1, J5 (transport, OAuth, annotations)
- **23 TypedRule detector files** — E1–E4, F1–F7, G1–G7, H1–H3, J2–J7, K1–K20, L1–L15, M1–M9, N1–N15, O4–O10, P1–P10, Q3–Q15

### Phase 2: YAML Fallback (deprecated — do NOT add new rules here)

| `detect.type` | Handler method | Status |
|---|---|---|
| `regex` | `runRegexRule()` | **DEPRECATED — all rules migrated to TypedRules** |
| `schema-check` | `runSchemaCheckRule()` | Legacy fallback only |
| `behavioral` | `runBehavioralRule()` | Legacy fallback only |
| `composite` | `runCompositeRule()` | Legacy fallback only |

**Adding a new rule**: Create a TypeScript implementation in `src/rules/implementations/`, register it in `src/rules/index.ts`. See `rules/CLAUDE.md` for the complete guide.

## Context → Text Mapping (`getTextsForContext`)

Legacy regex rules and some engine internals use `getTextsForContext` to map a context to searchable text:

| context value | What it searches |
|---|---|
| `tool_description` | Each tool's `.description` field |
| `parameter_description` | Each parameter's `.description` within `input_schema` |
| `parameter_schema` | Full stringified `input_schema` of each tool |
| `source_code` | The full concatenated source code string |
| `metadata` | Server name + description + all tool names joined |
| `server_initialize_fields` | `server.name` + `initialize_metadata.server_version` + `initialize_metadata.server_instructions` |

**`server_initialize_fields`** is the H2 context. Populated from `MCPConnector.enumerate()` via `client.getServerVersion()` + `client.getInstructions()`.

## Every Finding Must Have
```typescript
{
  rule_id: string        // e.g., "C1"
  severity: Severity     // critical | high | medium | low | informational
  evidence: string       // WHAT triggered it — specific text/pattern matched
  remediation: string    // HOW to fix it — from the rule YAML
  owasp_category?: string
  mitre_technique?: string
}
```
Findings without `evidence` are useless. The hook will not catch this — enforce it manually.

## Adding a New Composite Rule
1. Add a case to `runCompositeRule()` switch statement
2. The check name must match `detect.check` in the rule YAML
3. Add to the Engine Implementation Status table in `agent_docs/detection-rules.md`
4. Write test in `engine.test.ts`

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
