# MCP Sentinel — Technical Roadmap

_Last updated: 2026-04-07_
_Context: All 164 active rules migrated to TypedRules. 13 retired. Phase 4 (Test Overhaul) complete. Phase 6 (Documentation Cleanup) in progress._

## Current State (Post-Migration)

### All Rules Are TypedRule Implementations

Every active detection rule is a TypeScript `TypedRule` with structured analysis — AST taint tracking, capability graph algorithms, Shannon entropy, Levenshtein similarity, structural parsing, or linguistic scoring. **Zero YAML regex patterns remain.** YAML files in `rules/` contain metadata only (`detect.type: typed`).

| Analysis Technique | Rules Using It | Implementation |
|---|---|---|
| AST taint (source→sink with sanitizer detection) | C1, C2, C4, C5, C10, C12, C13, C14, C16, K9, J2, L9, K2, G7, J1, L4, L11, Q4 | `taint-ast.ts` (803 lines), `taint.ts` (676 lines) |
| Capability graph (DFS cycle, BFS reachability, centrality) | F1, F2, F3, F6, F7, I1, I2, I13, I16, G1, G5, H2, I7 | `capability-graph.ts` (761 lines) |
| Multi-signal linguistic scoring | A1–A5, A8, B1–B7 | `description-schema-detector.ts` |
| Unicode codepoint analysis | A6, A7 | `a6-unicode-homoglyph.ts` |
| Shannon entropy (secret detection) | C5, L9, G7 | `entropy.ts` (449 lines) |
| Damerau-Levenshtein similarity | D3, F5 | `similarity.ts` (477 lines) |
| Structural parsing (Dockerfile, k8s, JSON Schema) | P1–P7, J3, L5, L12, K10, L14 | `infrastructure-detector.ts`, `supply-chain-detector.ts` |
| Module/import resolution | L1, L2, L6, L7, L13, K3, K5, K8 | `module-graph.ts` (826 lines) |
| Factory-built structural rules | K1–K20, L3–L15, M2–M8, N1–N10, O4–O10, P8–P10, Q3–Q15 | `compliance-remaining-detector.ts` |
| Protocol structural analysis | M1, M6, M9, N4–N15, I3–I15, J3–J7 | `protocol-ai-runtime-detector.ts`, `protocol-surface-remaining-detector.ts` |

### 23 Detector Files (~13K Lines of Detection Logic)

All in `packages/analyzer/src/rules/implementations/`:

| Detector | Rules | Lines |
|----------|-------|-------|
| `c1-command-injection.ts` | C1 | ~200 |
| `tainted-execution-detector.ts` | C4, C12, C13, C16, K9, J2 | ~400 |
| `code-security-deep-detector.ts` | C2, C5, C10, C14 | ~600 |
| `code-remaining-detector.ts` | C3, C6–C9, C11, C15 | ~500 |
| `description-schema-detector.ts` | A1–A5, A8, B1–B7 | ~1200 |
| `a6-unicode-homoglyph.ts` | A6, A7 | ~300 |
| `a9-encoded-instructions.ts` | A9 | ~200 |
| `d3-typosquatting.ts` | D3 | ~200 |
| `dependency-behavioral-detector.ts` | D1–D7, E1–E4 | ~600 |
| `f1-lethal-trifecta.ts` | F1, F2, F3, F6, F7 | ~800 |
| `ecosystem-adversarial-detector.ts` | F4, F5, G6, H1, H3 | ~500 |
| `ai-manipulation-detector.ts` | G1, G2, G3, G5, H2 | ~600 |
| `g4-context-saturation.ts` | G4 | ~200 |
| `cross-tool-risk-detector.ts` | I1, I2, I13, I16 | ~500 |
| `config-poisoning-detector.ts` | J1, L4, L11, Q4 | ~400 |
| `secret-exfil-detector.ts` | L9, K2, G7 | ~400 |
| `supply-chain-detector.ts` | L5, L12, L14, K10 | ~400 |
| `advanced-supply-chain-detector.ts` | L1, L2, L6, L7, L13, K3, K5, K8 | ~800 |
| `infrastructure-detector.ts` | P1–P7 | ~600 |
| `protocol-ai-runtime-detector.ts` | M1, M6, M9, N4–N15 | ~800 |
| `protocol-surface-remaining-detector.ts` | I3–I15, J3–J7 | ~600 |
| `data-privacy-cross-ecosystem-detector.ts` | O4–O6, O8–O9, Q3–Q4, Q6–Q7, Q10, Q13 | ~500 |
| `compliance-remaining-detector.ts` | K1–K20, L3–L15, M2–M8, N1–N10, O4–O10, P8–P10, Q3–Q15 | ~1200 |

### Supporting Analysis Infrastructure

| Module | Lines | Purpose |
|---|---|---|
| `taint-ast.ts` | 803 | 3-pass interprocedural taint: collect functions → walk AST → resolve sinks |
| `taint.ts` | 676 | Lexical fallback taint analysis (when AST parsing fails) |
| `taint-python.ts` | ~400 | Python-specific taint via tree-sitter |
| `capability-graph.ts` | 761 | Directed graph with DFS cycle detection, BFS reachability, centrality scoring |
| `module-graph.ts` | 826 | Cross-file import resolution and export tracking |
| `entropy.ts` | 449 | Shannon entropy for secret detection, calibrated thresholds |
| `similarity.ts` | 477 | Multi-algorithm string distance for typosquatting |
| `schema-inference.ts` | ~300 | Semantic parameter classification (13 types), constraint density |
| `evidence.ts` | ~200 | EvidenceChainBuilder — fluent API for compliance-grade evidence chains |

### Retired Rules (13)

Retired due to high false-positive rates or duplicate coverage. YAML files remain with `enabled: false`. TypedRule registrations removed from engine.

O1, O2, O3, O7 (data-privacy), Q1, Q2, Q5, Q8, Q9, Q11, Q12, Q14 (cross-ecosystem), M3 (ai-runtime — duplicated by A1 linguistic scoring).

### Test Coverage

| Suite | Tests | Files |
|---|---|---|
| Analyzer (unit + category) | 1443 | 29 test files |
| Red-team (accuracy fixtures) | 49 | 1 test file |
| Attack-graph | 150 | 3 test files |
| **Total** | **1642** | **33 test files** |

- 262 evidence chain assertions across 11 category test files
- 55 benign corpus fixtures (zero false positives)
- Evidence validation script enforces ≥90% chain coverage

---

## Remaining Technical Gaps

| # | Gap | Impact | Status |
|---|---|---|---|
| **1** | **Pipeline drops evidence chains** — `analyze()` strips `metadata` before DB persistence | Critical | Evidence chains generated by rules but not persisted; compliance reports can't include proof |
| **2** | **JS/TS only for full AST taint** — Python MCP servers (~40% of ecosystem) get structural fallback | High | `taint-python.ts` exists but uses tree-sitter lexical analysis, not full interprocedural taint |
| **3** | **Single-file analysis** — no cross-module taint tracking in the pipeline | Medium | `module-graph.ts` exists but pipeline concatenates source into one blob |
| **4** | **50KB source cap** — large servers truncated | Medium | Some popular servers have 200KB+ source |
| **5** | **No published benchmark data** — can't prove detection superiority | High | `packages/benchmark/` exists but no published results |
| **6** | **No ecosystem intelligence report** — 12K+ servers scanned, data unpublished | High | `packages/reports/` exists but no published report |

---

## Next Priorities

### Priority 1: Wire Evidence Chains Through the Pipeline

**Why:** Rules already generate compliance-grade evidence (source→propagation→sink→impact + confidence + verification steps). But `pipeline.ts` calls `engine.analyze()` which strips metadata. The chains never reach the database, API, or web UI. Without this, the evidence chain infrastructure is test-only.

**What:**
1. `pipeline.ts` → call `analyzeRich()` or `analyzeWithProfile()` instead of `analyze()`
2. `findings` table → add `metadata JSONB` column (migration)
3. `api/` → return evidence chains in finding responses
4. `web/` → render evidence chains on server detail pages
5. `reports/` → include evidence chains in compliance report output

### Priority 2: Publish Ecosystem Intelligence Report

**Why:** We have 12K+ scanned servers. Nobody else has this dataset. The data IS the product.

**What:** Generate "State of MCP Security Q1 2026" using `packages/reports/`. Publish on website, submit to OWASP MCP project.

### Priority 3: Competitive Benchmark Publication

**Why:** "164 rules" means nothing without evidence of superior detection. Run `packages/benchmark/` against competitor tools and publish results.

### Priority 4: Layer 6 — Compliance & Enterprise

**What:** OWASP MCP Top 10 mapping complete, MITRE ATLAS mapping complete, EU AI Act readiness assessment, quarterly security report.

---

## What NOT to Build

| Temptation | Why Not |
|---|---|
| LLM-powered analysis | ADR-006: deterministic = auditable = enterprise-ready. Add only where a deterministic rule demonstrably fails (>5% FP rate) |
| Full Semgrep/CodeQL integration | Our taint engine is purpose-built for MCP patterns. General SAST tools have 10K rules for web apps — we need 164 rules for MCP servers |
| Runtime instrumentation beyond Layer 5 | Dynamic tester exists with consent gating. Don't duplicate |
| User authentication / billing | Post-seed. Registry is public read-only |
| Performance optimization | Correctness first. Optimize after 10K+ servers |
