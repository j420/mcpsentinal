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
  initialize_metadata?: {             // H2 surface — currently always undefined (P0 bug)
    server_version?: string | null
    server_instructions?: string | null
  }
}
```

## The 4 Rule Handler Types

| `detect.type` | Handler method | Used by |
|---|---|---|
| `regex` | `runRegexRule()` | A1–A9, B5, C1–C16, H1, H2 |
| `schema-check` | `runSchemaCheckRule()` | B1–B7, E1–E4 |
| `behavioral` | `runBehavioralRule()` | E1–E4, G6 |
| `composite` | `runCompositeRule()` | F1–F7, G1–G5, G7, H3, D-rules |

**Adding a new `detect.type`**: add a new `runXRule()` method, add a case to `runRule()`, add to the Engine Implementation Status table in `agent_docs/detection-rules.md`.

## Context → Text Mapping (`getTextsForContext`)

Each regex rule specifies a `context` — where to search for the pattern:

| context value | What it searches |
|---|---|
| `tool_description` | Each tool's `.description` field |
| `parameter_description` | Each parameter's `.description` within `input_schema` |
| `parameter_schema` | Full stringified `input_schema` of each tool |
| `source_code` | The full concatenated source code string |
| `metadata` | Server name + description + all tool names joined |
| `server_initialize_fields` | `server.name` + `initialize_metadata.server_version` + `initialize_metadata.server_instructions` |

**`server_initialize_fields`** is the H2 context. It currently receives no data because `initialize_metadata` is always `undefined`. See `packages/connector/CLAUDE.md` for the fix.

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
