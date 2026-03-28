# Sprint 1: Human Oversight — Migrate Rules from YAML Regex to TypeScript

## Mission

You are the **P8 Detection Rule Engineer** for MCP Sentinel, the world's most comprehensive MCP security intelligence registry. Your task is to migrate the **Human Oversight** risk domain rules from YAML regex patterns to proper TypeScript detection with production-grade test cases.

This domain maps to **EU AI Act Article 14 (Human Oversight)** — enforcement deadline August 2, 2026. Penalties up to 15M EUR / 3% turnover. This is the highest-priority migration.

## Context: What MCP Sentinel Is

MCP Sentinel scans every public MCP (Model Context Protocol) server, runs 177 detection rules against them, scores their security posture, and publishes results. The scan pipeline is: Discovery → Connection → Analysis → Scoring → Publication.

The analyzer (`packages/analyzer/`) runs detection in 2 phases:
- **Phase 1**: 5 specialized TypeScript engines (CodeAnalyzer, DescriptionAnalyzer, SchemaAnalyzer, DependencyAnalyzer, ProtocolAnalyzer) that do real program analysis
- **Phase 2**: YAML-interpreted fallback for rules not yet in TypeScript — this includes `runRegexRule()` which does raw string pattern matching

Rules with `detect.type: regex` in YAML are the migration targets. The goal is to replace regex string matching with TypeScript implementations that use AST parsing, taint tracking, structural analysis, and other real techniques.

## What You're Working With

### The AnalysisContext (input to every rule)

```typescript
interface AnalysisContext {
  server: { id: string; name: string; description: string | null; github_url: string | null };
  tools: Array<{
    name: string;
    description: string | null;
    input_schema: Record<string, unknown> | null;
    output_schema?: Record<string, unknown> | null;
    annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean } | null;
  }>;
  source_code: string | null;
  source_files?: Map<string, string> | null;
  dependencies: Array<{ name: string; version: string | null; has_known_cve: boolean; cve_ids: string[]; last_updated: Date | null }>;
  connection_metadata: { auth_required: boolean; transport: string; response_time_ms: number } | null;
  initialize_metadata?: { server_version?: string | null; server_instructions?: string | null };
  resources?: Array<{ uri: string; name: string; description?: string | null; mimeType?: string | null }>;
  prompts?: Array<{ name: string; description?: string | null; arguments?: Array<{ name: string; description?: string | null; required?: boolean }> }>;
  roots?: Array<{ uri: string; name?: string | null }>;
  declared_capabilities?: { tools?: boolean; resources?: boolean; prompts?: boolean; sampling?: boolean; logging?: boolean } | null;
  previous_tool_pin?: ServerToolPin | null;
}
```

### The TypedRule Interface (what you implement)

```typescript
interface TypedFinding {
  rule_id: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  evidence: string;
  remediation: string;
  owasp_category: string | null;
  mitre_technique: string | null;
  confidence: number; // 0.0–1.0
  metadata?: Record<string, unknown>;
}

interface TypedRule {
  readonly id: string;
  readonly name: string;
  analyze(context: AnalysisContext): TypedFinding[];
}
```

### Existing Analysis Toolkits Available

Located in `packages/analyzer/src/rules/analyzers/`:
- `taint-ast.ts` — TypeScript AST source→sink taint tracking
- `taint-python.ts` — Python AST taint via tree-sitter
- `taint.ts` — regex-based taint fallback
- `capability-graph.ts` — directed graph of tool capabilities
- `entropy.ts` — Shannon entropy, compression ratio
- `similarity.ts` — Levenshtein, Jaro-Winkler
- `unicode.ts` — homoglyph, confusable, zero-width detection
- `schema-inference.ts` — JSON Schema structural analysis
- `module-graph.ts` — cross-file import resolution

### Existing Typed Rule Examples

Look at these files for the implementation pattern:
- `packages/analyzer/src/rules/implementations/c1-command-injection.ts` — AST taint with regex fallback, confidence scoring
- `packages/analyzer/src/rules/implementations/a6-unicode-homoglyph.ts` — Unicode analysis
- `packages/analyzer/src/rules/implementations/a9-encoded-instructions.ts` — Entropy + encoding detection

### How Rules Get Registered

1. Create implementation in `packages/analyzer/src/rules/implementations/{id}-{name}.ts`
2. The file must call `registerTypedRule(new YourRule())` at module level
3. Add `import "./implementations/{id}-{name}.js";` to `packages/analyzer/src/rules/index.ts`
4. Update the rule's YAML `detect.type` from `regex` to `typed`, remove `patterns` and `context` fields

## Rules to Migrate

### Rule Q15 — A2A/MCP Protocol Boundary Confusion (PURE REGEX → TypeScript)

**Current YAML:** `rules/Q15-a2a-mcp-boundary-confusion.yaml`
**Status:** Pure regex, no engine coverage. Must build TypeScript implementation from scratch.

Read the YAML file to understand the current patterns and test cases. Then:

**What this rule detects:** MCP servers that also expose A2A (Agent-to-Agent) protocol endpoints, creating confusion about which protocol's trust model applies. An agent that authenticates via MCP may inadvertently trust A2A calls that bypass MCP's consent mechanisms.

**Analysis technique needed:** AST analysis of source code to detect:
1. Dual-protocol handler registration (MCP + A2A/gRPC/REST endpoints in same server)
2. Shared authentication context between protocols without explicit boundary declaration
3. Tool handlers accessible via both MCP and non-MCP routes without separate auth checks

**Evidence must include:** Which protocols are detected, which handlers are shared, what trust boundary is missing.

**Confidence model:**
- AST: dual-protocol handler detected with shared auth context → 0.90
- AST: dual-protocol detected but separate auth → 0.40 (informational)
- Regex fallback: pattern match only → 0.50

### Rules K4, K5 — Remove Regex Fallback (ENGINE+REGEX → remove regex path)

**K4 — Missing Human Confirmation for Destructive Operations**
**K5 — Auto-Approve / Bypass Confirmation Pattern**

These are already handled by `CodeAnalyzer` in Phase 1 (the engine emits findings with rule_id "K4" and "K5"). But their YAMLs still say `type: regex`, which means when the engine finds nothing, the regex fallback runs.

For these two rules:
1. Read the current YAML to understand the patterns
2. Verify the CodeAnalyzer already handles them (grep for `rule_id: "K4"` and `rule_id: "K5"` in `packages/analyzer/src/engines/code-analyzer.ts`)
3. Update the YAML `detect.type` from `regex` to `typed`
4. Remove the `patterns`, `context`, and `exclude_patterns` fields from the YAML
5. Ensure the TypeScript implementation already exists or create one

## Test Case Requirements

For Q15 (the new TypeScript implementation), create a test file at `packages/analyzer/__tests__/rules/q15-a2a-boundary.test.ts` with:

**Minimum 16 test cases (8 TP, 8 TN):**

True Positives (MUST detect):
1. Express server with both MCP handler and REST `/a2a/` endpoint sharing the same auth middleware
2. Fastify server registering MCP tools AND gRPC service on same port without separate auth
3. Python server with both MCP tool decorator and A2A agent card endpoint
4. Server importing both `@modelcontextprotocol/sdk` and `@google/a2a` with shared handler functions
5. Server where MCP tool handler calls A2A client methods using the same credentials
6. Server exporting functions used by both MCP tool registration and REST route handlers
7. Dual-protocol server with `app.use(authMiddleware)` applied globally (no per-protocol auth)
8. Server with MCP tools that proxy to internal A2A endpoints without re-authentication

True Negatives (MUST NOT detect):
1. Pure MCP server with no A2A/REST/gRPC references
2. Server that mentions "a2a" in comments or documentation only
3. Server with MCP tools and a separate, independent REST health check endpoint
4. Test file containing A2A protocol mocking for integration tests
5. Server with MCP and REST endpoints that have completely separate auth middleware per route
6. Server that imports A2A SDK but only uses it as a client (not exposing A2A endpoints)
7. Documentation file explaining A2A/MCP interoperability
8. Server with A2A references only in dependency names (not in handler code)

Edge Cases (include in either TP or TN as appropriate):
- Minified code where dual-protocol patterns are compressed
- Dynamic route registration (`app[method](path, handler)`)
- Framework-specific patterns (NestJS, Hono, Elysia)
- Shared middleware that's imported from a separate file

For K4 and K5 (YAML cleanup), verify existing test coverage in `packages/analyzer/__tests__/engine.test.ts`.

## Files to Create/Modify

| File | Action |
|------|--------|
| `packages/analyzer/src/rules/implementations/q15-a2a-boundary.ts` | **Create** — TypedRule implementation |
| `packages/analyzer/src/rules/index.ts` | **Modify** — add import for q15 |
| `packages/analyzer/__tests__/rules/q15-a2a-boundary.test.ts` | **Create** — 16+ test cases |
| `rules/Q15-a2a-mcp-boundary-confusion.yaml` | **Modify** — change `type: regex` to `type: typed`, remove patterns |
| `rules/K4-missing-human-confirmation.yaml` | **Modify** — change `type: regex` to `type: typed`, remove patterns |
| `rules/K5-auto-approve-bypass.yaml` | **Modify** — change `type: regex` to `type: typed`, remove patterns |

## Verification Checklist

1. `pnpm typecheck` — all 21 packages pass
2. `pnpm test --filter=@mcp-sentinel/analyzer` — all tests pass including new q15 tests
3. `bash tools/scripts/validate-rules.sh` — all 177 rules validate
4. The Q15 TypedRule produces findings with confidence scores and evidence that a human can verify
5. K4 and K5 YAML files no longer contain `patterns` or `context` fields
6. No rule behavior regression — existing findings still produced by the CodeAnalyzer engine

## What NOT to Do

- Do NOT add LLM API calls — all analysis is deterministic
- Do NOT write YAML regex patterns — the whole point is replacing them with TypeScript
- Do NOT modify engine.ts — the `typed` dispatch is already wired up
- Do NOT change the rule IDs (Q15, K4, K5) — they're referenced in findings, scores, fixtures, and documentation
- Do NOT add dependencies without checking if an existing analyzer toolkit already provides the capability
