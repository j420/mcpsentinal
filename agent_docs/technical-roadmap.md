# MCP Sentinel — Technical Roadmap

_Last updated: 2026-04-23_
_Context: Post-Phase-5. All 164 active rules are Rule Standard v2 `TypedRuleV2` implementations with mandatory `EvidenceChain`. 13 retired. Phase 1 chunks 1.1–1.28 (rule migration + v1-API deletion), Phase 2 (credibility tests), Phase 4 (CVE replay corpus, PR #204), and Phase 5 (signed regulator-facing compliance reports, PR #205) all shipped. Phase 3 (compliance-agents hallucination firewall) is parked._

_Owner: P4 Registry Architect._
_Canonical roadmap doc: `docs/plans/full-migration-plan-2026-04-20.md`._

## Current State (Post-Phase-5)

### Rule Standard v2 — one directory per rule

All 164 active detection rules live at `packages/analyzer/src/rules/implementations/<rule-id>/` as `TypedRuleV2` classes with a mandatory structured `EvidenceChain` (source → propagation* → sink → mitigation → impact). The Phase 1 chunk 1.28 cutover deleted the v1 `TypedRule` interface, `V1RuleAdapter`, and the four legacy YAML dispatchers (`runRegexRule` / `runSchemaCheckRule` / `runBehavioralRule` / `runCompositeRule`) from `packages/analyzer/src/engine.ts` — engine shrank from 2177 → 463 lines. **Zero YAML regex patterns remain. Zero regex literals in rule authoring. Two always-fail CI guards (`no-static-patterns`, `charter-traceability`) prevent regression.**

Each rule directory conforms to:

```
packages/analyzer/src/rules/implementations/<rule-id>/
├── CHARTER.md                ← ≤120 lines, ≥3 lethal edge cases, interface_version: "2.0", evidence_contract, mutations_survived
├── gather.ts                 ← deterministic fact collection, no regex literals, no string arrays > 5
├── verification.ts           ← named VerificationStep factories, each targets a structured Location
├── index.ts                  ← class implements TypedRuleV2, registers via registerTypedRuleV2 at module load
├── data/*.ts                 ← typed vocabulary / target-lookup tables
├── __fixtures__/             ← ≥3 true-positive + ≥2 true-negative TypeScript files
└── __tests__/index.test.ts   ← exercises each CHARTER lethal edge case + chain shape
```

### Analysis technique distribution

| Technique | Rules | Supporting modules |
|---|---|---|
| AST taint (source → sink, sanitizer-aware) | C1, C2, C4, C5, C10, C12, C13, C14, C16, K9, J2, L9, K2, G7, J1, L4, L11, Q4 | `taint-ast.ts`, `taint.ts`, `_shared/taint-rule-kit/` |
| Capability graph (DFS cycle, BFS reachability, centrality) | F1, F2, F3, F6, F7, I1, I2, I13, I16, G1, G5, H2, I7 | `capability-graph.ts` |
| Multi-signal linguistic scoring (noisy-OR) | A1–A5, A8, B1–B7, G2, G3, G5, J6 | `_shared/ai-manipulation-phrases.ts`, framework-specific vocabulary files |
| Unicode codepoint analysis | A6, A7 | per-rule `a6-unicode-homoglyph/`, `a7-zero-width-injection/` |
| Shannon entropy (secret detection) | C5, L9, G7 | `entropy.ts` |
| Damerau-Levenshtein + Jaro-Winkler similarity | D3, F5 | `similarity.ts` |
| Structural parsing (Dockerfile, k8s YAML, JSON Schema) | P1–P7, J3, J4, J7, L5, L12, K10, L14 | per-rule structural parsers |
| Module/import resolution (cross-file) | L1, L2, L6, L7, L13, K3, K5, K8 | `module-graph.ts`, `_shared/dependency-location.ts` |
| Protocol structural analysis (JSON-RPC shapes, MCP catalogue) | M1, M6, M9, N4–N15, I3–I15, J3–J7 | `_shared/protocol-shape-catalogue.ts`, `_shared/mcp-method-catalogue.ts` |

### Five specialized engines

`packages/analyzer/src/engines/` keeps five analyzers for categories where cross-rule shared state is economical: `CodeAnalyzer`, `DescriptionAnalyzer`, `SchemaAnalyzer`, `DependencyAnalyzer`, `ProtocolAnalyzer`. Each defers to `TypedRuleV2` via `hasTypedRule()` check in `engine.ts` to avoid double-counting.

### Supporting analysis infrastructure

| Module | Purpose |
|---|---|
| `taint-ast.ts` | 3-pass interprocedural taint: function index → AST walk → sink resolution |
| `taint.ts` | Lexical fallback taint analysis when AST parsing fails |
| `taint-python.ts` | Python-specific taint via tree-sitter |
| `capability-graph.ts` | Directed graph with DFS cycle, BFS reachability, centrality |
| `module-graph.ts` | Cross-file import resolution and export tracking |
| `entropy.ts` | Shannon entropy + chi-squared + compression-ratio for secret detection |
| `similarity.ts` | Damerau-Levenshtein + Jaro-Winkler + visual-confusable replay |
| `evidence.ts` | `EvidenceChainBuilder` — fluent API for building the regulator-grade chain |
| `location.ts` | Structured `Location` kinds (tool / parameter / source / initialize / resource / prompt / capability / schema / config / dependency) |
| `_shared/` | Cross-rule primitives: `taint-rule-kit/`, `ai-manipulation-phrases.ts`, `protocol-shape-catalogue.ts`, `mcp-method-catalogue.ts`, `data-exfil-sinks.ts`, `dependency-location.ts` |

### Retired rules (13)

Retired during migration due to high false-positive rates or duplicate coverage. YAML files remain in `rules/` with `enabled: false`. No `TypedRuleV2` registration.

O1, O2, O3, O7 (data-privacy); Q1, Q2, Q5, Q8, Q9, Q11, Q12, Q14 (cross-ecosystem); M3 (ai-runtime — duplicated by A1 linguistic scoring).

I14 (rolling capability drift) was disabled during Phase 2.1 bugfix pending a `TypedRuleV2` implementation; YAML stays `enabled: false` until the rule ships.

### Test coverage (post-Phase-5)

| Suite | Test files | Tests |
|---|---|---|
| Analyzer (per-rule + category + harnesses) | 162 | ~2853 |
| Compliance-reports (data-model, renderers, kill-chain, badges) | 16 | 142 |
| API (REST endpoints incl. signed compliance routes) | 3 | 108 |
| Red-team (accuracy runner + mutation suite + CVE corpus harness + 22 CVE cases) | 4 | ~100 |
| Attack-graph (KC01–KC07 scoring + engine + narratives) | 5 | 150 |
| **Total (core packages)** | **190** | **~3350** |

Phase 2 infrastructure preserves credibility:
- **Evidence-integrity harness** — 4 assertion classes enforced on every rule (Location resolution per-kind, AST reachability, confidence derivation, CVE manifest completeness)
- **Adversarial mutation suite** — 8 TS-AST mutations × 163 rules; aggregate survival rate 95.4%; always-fail parity guard catches regressions
- **Benign corpus** — 163 fixtures across four buckets (anthropic-official, smithery-top, canonical-non-mcp, edge-of-spec); zero critical/high findings tolerated
- **Per-rule accuracy dashboard** — `rules/accuracy-targets.yaml` pins precision/recall per rule; `.github/workflows/accuracy.yml` fails CI on regression. Baseline P=93.9%, R=49.2%.

Phase 4 infrastructure preserves regulator credibility:
- **CVE replay corpus** — 22 cases (16 CVEs + 6 research attacks) at `packages/red-team/src/cve-corpus/cases/`; auto-generated coverage doc at `docs/cve-coverage.md`; 20 unique rules covered with real-world replay evidence; 143 honest-gap rules transparently listed.

---

## Recently Shipped

### Phase 1 (chunks 1.1–1.28) — Rule Standard v2 migration + v1 API deletion

Migrated all 164 active rules from YAML regex / v1 `TypedRule` to `TypedRuleV2` per-rule directories. Deleted v1 API + 4 YAML dispatchers. Shipped over 6 parallel-agent waves on `claude/phase-1/*` branches.

### Phase 2 — Credibility tests (PR #203)

Evidence-integrity harness, mutation suite, benign corpus expansion (55 → 163), per-rule accuracy dashboard with CI regression gate.

### Phase 4 — CVE replay corpus (PR #204)

Harness contract at `docs/standards/cve-replay-corpus-spec.md`. 22 replay cases proving 20 unique rules catch real published attacks — 16 CVE cases (CVE-2025-6514, 6515, 53109, 53110, 53773, 54135, 59536, 59944, 68143, 68144, 68145, 2017-5941, 30066, 2026-21852, 22785, 29787) + 6 research replays (Embrace-The-Red, Invariant Labs, Trail of Bits, CyberArk FSP+ATPA, MPMA). Auto-generated `docs/cve-coverage.md`.

### Phase 5 — Regulator-facing signed compliance reports (PR #205)

New package `packages/compliance-reports/`: data model + RFC 8785 canonical JSON + HMAC-SHA256 attestation + 7 framework registries + HTML/PDF/JSON renderers + kill-chain narrative synthesizer + 7 framework badge SVGs. Signed API endpoints at `packages/api` (`/api/v1/servers/:slug/compliance/:framework.{json,html,pdf}` + `/badge.svg`). Every response HMAC-SHA256 attested; signature in response headers AND rendered body; regulators verify offline.

---

## Remaining Technical Gaps

| # | Gap | Impact | Path forward |
|---|---|---|---|
| 1 | **Phase 3 parked** — compliance-agents LLM verdicts have no hallucination-firewall test suite | High | Judge triad (26×3=78 tests), LLM-replay adversarial corpus (20 recorded bad responses), confidence-cap enforcement test |
| 2 | **Python taint fidelity** — `taint-python.ts` uses tree-sitter lexical analysis, not full interprocedural taint | Medium | Port the JS/TS 3-pass model to Python AST when ~40% Python ecosystem servers start dominating scan failures |
| 3 | **Single-file source analysis** — pipeline concatenates source into one blob | Medium | `module-graph.ts` exists; pipeline needs to pass per-file source map instead of concatenation |
| 4 | **50 KB source cap** — large servers get truncated | Medium | Raise to 250 KB + document truncation in coverage band |
| 5 | **Production signing key unset** — `COMPLIANCE_SIGNING_KEY` + `COMPLIANCE_SIGNING_KEY_ID` not yet in Railway env | High (launch-blocker) | Generate HMAC-SHA256 key, set env vars, validate signed endpoints return `X-MCP-Sentinel-Warning: dev-key-in-use` is absent |
| 6 | **API route → KC→CVE projection** hardcodes empty `cve_evidence_ids` | Medium | Wire `KILL_CHAIN_TO_CVE_PATTERNS` join in `compliance-report-routes.ts::toKillChainNarrative` |
| 7 | **No published benchmark data** — `packages/benchmark/` built, no results published | High | Run competitor comparison suite; publish in "State of MCP Security" |
| 8 | **No published ecosystem intelligence report** — 12K+ servers scanned, data unpublished | High | Generate Q2 2026 report via `packages/reports/` |
| 9 | **ASI10 coverage gap** — out of scope for an MCP scanner (training-pipeline attack surface) | Intentional | Documented honest gap in `packages/compliance-reports/src/frameworks/owasp_asi.ts` |
| 10 | **KC07 (DB privesc → theft) no Phase 4 exemplar** — attack-graph engine still scores it from preconditions | Low | Phase 6 corpus expansion (DB-privesc-via-MCP case); honest gap in `kill-chain/data/kc-cve-mapping.ts` |

---

## Next Priorities

### Priority 1 — Resume Phase 3 (hallucination firewall)

**Why:** Phase 5 compliance reports can carry LLM-augmented findings (via `packages/compliance-agents/`), but without Phase 3 the credibility claim "every LLM verdict is re-validated by a deterministic judge" has no test evidence. Regulators auditing a signed report can't verify that claim.

**What:** 3 chunks per main plan — 3.1 judge triad (78 tests), 3.2 LLM-replay corpus (20 recorded bad responses + replay runner), 3.3 confidence-cap enforcement (every LLM finding ≤ 0.85 with `analysis_technique: "llm-reasoning"` tag).

### Priority 2 — Publish ecosystem intelligence report

**Why:** We have 12K+ scanned servers. Nobody else has this dataset. The data IS the product.

**What:** Generate "State of MCP Security Q2 2026" via `packages/reports/`. Publish on website, submit to OWASP MCP project.

### Priority 3 — Competitive benchmark publication

**Why:** "164 rules" means nothing without evidence of superior detection. Run `packages/benchmark/` against competitor tools; publish results.

### Priority 4 — Production compliance signing keys

**Why:** Launch-blocker. Without `COMPLIANCE_SIGNING_KEY` + `COMPLIANCE_SIGNING_KEY_ID` in Railway env, every signed report carries `X-MCP-Sentinel-Warning: dev-key-in-use` — acceptable for development, not for regulators.

---

## What NOT to Build

| Temptation | Why Not |
|---|---|
| LLM-powered analysis outside `packages/compliance-agents/` | ADR-009 scopes the exception. Deterministic = auditable = regulator-ready. Add elsewhere only if a deterministic rule shows >5% FP rate in the accuracy dashboard |
| Full Semgrep / CodeQL integration | The AST taint + capability graph engines are purpose-built for MCP patterns. General SAST has 10K rules for web apps — we need 164 rules for MCP servers |
| Runtime instrumentation beyond Layer 5 | `packages/dynamic-tester/` exists with consent gating. Don't duplicate |
| User authentication / billing | Post-seed. Registry stays public read-only |
| Performance optimization | Correctness first. Optimize when servers exceed 50K |
