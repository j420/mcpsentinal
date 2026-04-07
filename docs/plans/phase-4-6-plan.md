# MCP Sentinel v2: Phase 4 (Test Overhaul) + Phase 6 (Documentation Cleanup)

## Context

Phase 3 (Rule Migration) is COMPLETE. All 164 active rules are TypedRule implementations. 13 rules retired. CI passing after test count fix (177→164). Phase 5 (API & UI) is SKIPPED.

**Current test state (28 test files, ~1282 tests):**
- All 164 active rule IDs appear in at least one test file — no completely untested rules
- BUT ~70% of tests are shallow (only check `findings.length` or `findings.some()`)
- Only ~12 files have evidence chain assertions (`.chain`, confidence, verification_steps)
- V2 migrated rules (k1, k4, k6, k7, k17, m4, m5, o4, q10, batch2) have deep tests — these are the reference pattern
- engine.test.ts (280 tests) and category-*.test.ts files are almost entirely shallow
- Existing benign patterns scattered across files but no dedicated benign corpus
- Red-team infra exists (`packages/red-team/`), accuracy.yml workflow exists (schedule disabled)

**Current documentation state:**
- 6 files have stale "177" references → need "164 active (13 retired)"
- `agent_docs/technical-roadmap.md` is entirely pre-migration ("94 rules still on regex")
- `packages/scanner/CLAUDE.md` says "103 detection rules" (wrong)
- detection-rules.md Engine Status tables still reference `runRegexRule` handlers

**Goal**: Upgrade test quality to evidence-chain standard, formalize benign corpus, enable CI precision gate, fix all stale documentation.

---

## APPENDIX A: Complete 177-Rule Migration Manifest

Every rule. Where it is now. Where it's going. Whether it has tests.

### Currently DEEP rules (72 rules — keep, upgrade tests only)

| Rule IDs | File | Current Technique | Has Tests? | Action |
|---|---|---|---|---|
| C1 | c1-command-injection.ts | AST taint (3-phase) | YES + evidence chain | ✅ Reference impl. Upgrade to TypedRuleV2. |
| C4, C12, C13, C16, J2, K9 | tainted-execution-detector.ts | AST taint (parameterized) | YES (except K9) | Upgrade to TypedRuleV2. Add K9 tests. |
| C2, C5, C10, C14 | code-security-deep-detector.ts | AST taint + entropy + structural | YES | Upgrade to TypedRuleV2. |
| C3, C6-C9, C11, C15 | code-remaining-detector.ts | AST taint + structural | YES | Upgrade to TypedRuleV2. |
| A1-A5, A8, B1-B7 | description-schema-detector.ts | Linguistic Noisy-OR + schema inference | YES | Upgrade to TypedRuleV2. Already genuine analysis. |
| A6, A7 | a6-unicode-homoglyph.ts | Unicode codepoint analysis | YES | Upgrade to TypedRuleV2. |
| A9 | a9-encoded-instructions.ts | Shannon entropy + chi-squared | YES | Upgrade to TypedRuleV2. |
| D3 | d3-typosquatting.ts | 5-algorithm similarity ensemble | NO | Upgrade + ADD TESTS. |
| D1, D2, D4-D7 | dependency-behavioral-detector.ts | CVE audit + similarity + structural | YES | Upgrade to TypedRuleV2. |
| E1-E4 | dependency-behavioral-detector.ts | Behavioral thresholds | YES | Upgrade to TypedRuleV2. |
| F1, F7 | f1-lethal-trifecta.ts | Capability graph + DFS | YES (F1 only) | Upgrade. Add F7 tests. |
| F2, F3, F6 | f1-lethal-trifecta.ts | Stubs (emitted by F1) | NO | Keep as stubs — parent rule emits findings. Add integration tests. |
| F4, F5, G6, H1, H3 | ecosystem-adversarial-detector.ts | Levenshtein + OAuth pattern + structural | YES (except G6) | Upgrade. Add G6 tests. |
| G1, G2, G3, G5, H2 | ai-manipulation-detector.ts | Linguistic analysis | YES | Upgrade to TypedRuleV2. |
| G4 | g4-context-saturation.ts | Context window analysis | NO | Upgrade + ADD TESTS. |
| I1, I13, I16 | cross-tool-risk-detector.ts | Capability graph + schema | YES | Upgrade to TypedRuleV2. |
| I2 | cross-tool-risk-detector.ts | Stub (emitted by I1) | NO | Keep as stub. Add integration test. |
| L5, L12, K10 | supply-chain-detector.ts | JSON structural parsing | NO (L5, L12) | Upgrade + ADD TESTS. |
| L14 | supply-chain-detector.ts | Stub (emitted by L5) | NO | Keep as stub. Add integration test. |
| L1, L2, L6, L7, L13, K3, K5, K8 | advanced-supply-chain-detector.ts | AST taint + import resolution | YES (partial) | Upgrade. Add missing tests. |
| J1, L4, L11, Q4 | config-poisoning-detector.ts | AST taint + structural config | YES (J1 only) | Upgrade. Add L4, L11, Q4 tests. |
| L9, K2, G7 | secret-exfil-detector.ts | AST taint + entropy | YES (L9 only) | Upgrade. Add K2, G7 tests. |
| O5, O9 | data-privacy-cross-ecosystem-detector.ts | AST taint (useTaint: true) | YES | Upgrade to TypedRuleV2. |

### Currently REGEX rules — must migrate to dynamic analysis (105 rules)

These are the rules that need real analysis techniques replacing their regex patterns.

#### Batch 1: Taint Migration (~18 rules)
Rules that grep source code for dangerous patterns but should trace data flow.

| Rule ID | Current Regex | Target Technique | What Changes |
|---|---|---|---|
| K1 | `/console\.log.*request/` | **AST structural** — find console.log inside request handlers, cross-check logger imports | Scoped to handlers, cross-checks deps |
| K4 | `/delete.*\(.*\)(?!.*confirm)/` | **Schema inference** — find destructive tools missing confirmation parameters | Tool capability classification |
| K6 | `/scope.*\*/` | **AST taint** — trace OAuth scope from user input to grant request | Data flow proof |
| K7 | `/token.*expire.*never/` | **AST structural** — find token creation without TTL/rotation | Cross-checks crypto library usage |
| K11 | `/require\(.*\)(?!.*verify)/` | **AST structural** — find dynamic requires without integrity checks | Import graph analysis |
| K13 | `/res\.send\(.*\)/` | **AST taint** — trace tool output from external source to response | Data flow proof |
| K15 | `/shared.*state.*write/` | **Capability graph** — detect mutual write-read state across tools | Graph reachability |
| K17 | `/async.*(?!.*timeout)/` | **AST structural** — find async handlers without timeout wrappers | Control flow analysis |
| K18 | `/read.*sensitive.*send/` | **AST taint** — trace sensitive reads to tool responses | Cross-trust-boundary flow |
| L8 | `/from.*latest/` | **Structural** — parse Dockerfile FROM, check tag mutability | Config file parsing |
| L10 | `/integrity/` absence check | **Structural** — check lockfile presence + integrity hashes | Package manifest analysis |
| L15 | `/postinstall/` | **AST structural** — parse package.json scripts, trace execution | Script analysis |
| M1 | `/system.*prompt/` | **Linguistic Noisy-OR** — multi-signal LLM control token scoring | Multiple independent signals |
| M3 | `/reasoning.*chain/` | **Linguistic Noisy-OR** — reasoning chain manipulation signals | Multiple independent signals |
| M4 | `/model.*select/` | **Linguistic Noisy-OR** — model selection manipulation | Multiple independent signals |
| M5 | `/fine.?tun/` | **Linguistic Noisy-OR** — fine-tuning abuse signals | Multiple independent signals |
| O4 | `/PII.*collect/` | **AST taint** — trace PII field reads to storage/network sinks | Data flow proof |
| Q10 | `/cross.*protocol/` | **Capability graph** — detect cross-protocol bridge patterns | Graph structure analysis |

#### Batch 2: Structural Migration (~22 rules)
Rules that match patterns but should parse structure (Dockerfiles, YAML, JSON configs).

| Rule IDs | Target Technique | What Changes |
|---|---|---|
| P8-P10 | **Structural Docker/K8s parsing** — parse as data structures, not regex | Config file parser |
| N1-N3, N7, N8, N10 | **Structural JSON-RPC parsing** — parse protocol message structure | Protocol parser |
| K12 | **Schema inference** — classify tool output schemas for executable content | Schema analysis |
| K14 | **Capability graph** — trace credential flow through shared state nodes | Graph path analysis |
| K16 | **AST structural** — detect recursive calls without depth guards | Control flow |
| K19 | **Structural Docker** — parse security options, capabilities, user directives | Config parser |
| K20 | **AST structural** — check log calls for required context fields | Scope analysis |
| L3 | **Structural Docker** — parse FROM instruction, check base image provenance | Config parser |
| M2 | **Linguistic Noisy-OR** — multi-signal token manipulation scoring | Independent signals |
| M7, M8 | **Linguistic Noisy-OR** — AI runtime exploitation signals | Independent signals |

#### Batch 3: Protocol/Linguistic Migration (~25 rules)
Protocol surface and cross-ecosystem rules.

| Rule IDs | Target Technique | What Changes |
|---|---|---|
| I3-I12, I14, I15 | Already individual classes with structural analysis — upgrade evidence chains to TypedRuleV2 | Evidence chain enforcement |
| J3-J7 | Already individual classes — upgrade to TypedRuleV2 + deeper schema analysis for J3 | Evidence chain enforcement |

#### Batch 4: Data Privacy / Cross-Ecosystem (~40 rules)
The largest regex batch — `makePatternRule()` factory rules.

| Rule IDs | File | Target Technique | What Changes |
|---|---|---|---|
| O1-O3, O7 | data-privacy-cross-ecosystem-detector.ts | **AST taint** — trace data reads to exfil sinks | Data flow proof |
| O6, O8, O10 | data-privacy-cross-ecosystem-detector.ts | **AST taint** — trace privacy-relevant data flows | Data flow proof |
| Q1-Q3, Q5-Q9, Q11, Q13 | data-privacy-cross-ecosystem-detector.ts | **Capability graph + linguistic** — cross-protocol bridge detection | Graph + multi-signal |
| Q12, Q14, Q15 | compliance-remaining-detector.ts | **Structural** — parse config structures | Config parser |

#### Batch 5: Compliance Remaining (~24 rules from `buildRule()` factory)

| Rule IDs | Target Technique |
|---|---|
| K1, K4, K6, K7, K11-K20 | See Batch 1 above — each gets its own technique |
| L3, L8, L10, L15 | See Batch 1/2 above |
| M2, M4, M5, M7, M8 | Linguistic Noisy-OR |
| N1-N3, N7, N8, N10 | Structural JSON-RPC parsing |
| O4, O6, O8, O10 | AST taint |
| P8-P10 | Structural Docker/K8s |

### Rule Retirement Candidates (~10-15 rules)

Rules where regex IS the entire detection (no structural insight possible) should be retired:

- Rules that just check "does this string appear in code" with no context
- Rules with >50% estimated false-positive rate
- Rules duplicating coverage from deeper rules

Each retired rule: `enabled: false` in YAML with rationale. Rule count drops to ~160-165 genuine rules.

---

## APPENDIX B: Complete Test Gap Register

### 37 Untested Rules (need new tests)

| Category | Untested Rules | Detector File |
|---|---|---|
| D | D3 | d3-typosquatting.ts |
| F | F2, F3, F6, F7 | f1-lethal-trifecta.ts (stubs + F7) |
| G | G4, G6, G7 | g4-context-saturation.ts, ecosystem-adversarial, secret-exfil |
| I | I2, I8, I10, I13, I14 | cross-tool-risk (stub), protocol-surface-remaining |
| J | J3, J6 | protocol-surface-remaining |
| K | K4, K9, K10, K11, K13, K15, K17, K18 | compliance-remaining, tainted-execution, supply-chain |
| L | L4, L5, L8, L10, L11, L12, L14, L15 | config-poisoning, supply-chain |
| M | M1, M3, M4, M5 | protocol-ai-runtime |
| O | O4 | data-privacy-cross-ecosystem |
| Q | Q10 | compliance-remaining |

### Test Quality Upgrade: Evidence Chain Assertions

**Currently 6/177 rules** have evidence chain tests. ALL rules need this pattern:

```typescript
// REQUIRED test template for every rule
it("K1: detects console.log in request handler", () => {
  const findings = analyzeRule("K1", ctx);

  // 1. Finding fired
  expect(findings.length).toBe(1);

  // 2. Evidence chain structure (MANDATORY)
  const chain = findings[0].chain;
  expect(chain).toBeDefined();
  expect(chain.links.some(l => l.type === "source")).toBe(true);
  expect(chain.links.some(l => l.type === "sink")).toBe(true);

  // 3. Evidence specificity (not generic "pattern matched")
  const source = chain.links.find(l => l.type === "source")!;
  expect(source.observed).toContain("console.log");
  expect(source.location).toMatch(/line \d+/);

  // 4. Confidence calibration
  expect(chain.confidence).toBeGreaterThan(0.60);
  expect(chain.confidence).toBeLessThan(0.95);
  expect(chain.confidence_factors.length).toBeGreaterThanOrEqual(2);

  // 5. Verification steps
  expect(chain.verification_steps.length).toBeGreaterThanOrEqual(1);
  expect(chain.verification_steps[0].target).toMatch(/source_code:\d+/);
});

// TRUE NEGATIVE (every rule needs at least 2)
it("K1: does NOT fire when pino is used", () => {
  const findings = analyzeRule("K1", pinoCtx);
  expect(findings.length).toBe(0);
});

// CONFIDENCE ORDERING (every rule)
it("K1: confidence higher without logger deps", () => {
  const [f1] = analyzeRule("K1", noLoggerCtx);
  const [f2] = analyzeRule("K1", withLoggerCtx);
  expect(f1.chain.confidence).toBeGreaterThan(f2.chain.confidence);
});
```

### Per-Rule Test Minimums

| Technique | True Positives | True Negatives | Edge Cases | Evidence Assertions |
|---|---|---|---|---|
| AST taint | 3 | 3 | 2 | source→propagation→sink path |
| Structural | 2 | 2 | 1 | scope containment |
| Schema-inference | 2 | 2 | 1 | capability classification |
| Linguistic Noisy-OR | 2 | 2 | 1 | individual signal scores |
| Capability-graph | 2 | 2 | 1 | graph edges/paths |

---

## Phase 1: Engine Foundation (Week 1-2)

### 1.1 TypedRuleV2 Interface
**File**: `packages/analyzer/src/rules/base.ts`

```typescript
interface TypedRuleV2 {
  readonly id: string;
  readonly name: string;
  readonly requires: RuleRequirements;
  readonly technique: AnalysisTechnique;
  analyze(context: AnalysisContext): RuleResult[];
}

interface RuleResult {
  rule_id: string;
  severity: Severity;
  owasp_category: OwaspCategory | null;
  mitre_technique: string | null;
  remediation: string;
  chain: EvidenceChain;  // MANDATORY — not optional metadata
}
```

- `chain` is required, not buried in `metadata?: Record<string, unknown>`
- `requires` lets engine skip rules when data unavailable
- Backward-compat adapter wraps existing TypedRule during migration

### 1.2 Analysis Coverage Tracking
**File**: `packages/analyzer/src/engine.ts`

```typescript
interface AnalysisCoverage {
  had_source_code: boolean;
  had_connection: boolean;
  had_dependencies: boolean;
  techniques_run: AnalysisTechnique[];
  rules_executed: number;
  rules_skipped_no_data: number;
  coverage_ratio: number;
  confidence_band: "high" | "medium" | "low" | "minimal";
}
```

### 1.3 Remove YAML Detection Dispatch
- Remove `runRegexRule()`, `runSchemaCheckRule()`, `runBehavioralRule()`, `runCompositeRule()` from engine.ts (~1400 lines dead code)
- All detection through TypedRuleV2.analyze() exclusively
- Keep YAML files for metadata only

---

## Phase 2: Scoring v2 (Week 2)

### 2.1 Split config_score (141 rules → 7 balanced sub-scores)

| Sub-Score | Rules | Technique |
|---|---|---|
| `code_score` | C1-C16 (16) | AST taint |
| `description_score` | A1-A9 (9) | Linguistic + entropy |
| `schema_score` | B1-B7 (7) | Schema inference |
| `dependency_score` | D1-D7 (7) | Similarity + CVE |
| `ecosystem_score` | E1-E4, F1-F7, I13 (12) | Capability graph + behavioral |
| `protocol_score` | H1-H3, I1-I16 (19) | Structural + protocol |
| `adversarial_score` | G1-G7, J1-J7 (14) | Adversarial + threat intel |
| `compliance_score` | K1-K20 + remaining L-Q (~93) | Mixed — per-rule technique |

### 2.2 Coverage-Aware Scoring
Score display: `"85/100 (high confidence)"` vs `"85/100 (low confidence)"`
- **high**: coverage_ratio ≥ 0.80 + source_code + connection
- **medium**: coverage_ratio ≥ 0.60
- **low**: coverage_ratio ≥ 0.30
- **minimal**: < 0.30

---

## Phase 3: Rule Migration (Week 3-5)

Execute the migration manifest from Appendix A. Order:
1. **Batch 1** (18 taint rules) — highest impact, uses existing `analyzeASTTaint()` infra
2. **Batch 2** (22 structural rules) — build Docker/K8s/JSON-RPC parsers
3. **Batch 3** (25 protocol rules) — mostly evidence chain upgrades
4. **Batch 4** (40 data-privacy/cross-eco) — largest batch, mixed techniques
5. **Retire** ~10-15 rules that are pure string-matching with no path to real analysis

Each rule migrated independently — one PR per batch, tests green before proceeding.

---

## Phase 4: Test Overhaul

### 4.1 — Upgrade Shallow Tests to Evidence Chain Standard (Batch A: Category Tests)

**Target files** (currently shallow — only check `findings.some()` or `findings.length`):

| File | Tests | What to upgrade |
|------|-------|-----------------|
| `__tests__/category-protocol-surface.test.ts` | 27 | I1, I3-I7, I9, I11, I12, I15, I16 — add `.chain` structure, confidence range, verification steps |
| `__tests__/category-ai-runtime-protocol-edge.test.ts` | 25 | M1, M6, M9, N4-N15 — add evidence chain assertions |
| `__tests__/category-code-analysis.test.ts` | 50 | C1-C16 — add source→sink taint path assertions |
| `__tests__/category-dependency-behavioral.test.ts` | 39 | D1-D7, E1-E4 — add chain structure |
| `__tests__/category-description-analysis.test.ts` | 30 | A1-A9 — add linguistic signal assertions |
| `__tests__/category-schema-analysis.test.ts` | 24 | B1-B7 — add schema inference evidence |
| `__tests__/category-ecosystem-adversarial.test.ts` | 27 | F1-F7, G1-G7, H1-H3 — add capability graph evidence |
| `__tests__/category-threat-compliance-supply.test.ts` | 51 | J1-J7, K-rules, L-rules — add chain evidence |
| `__tests__/category-privacy-infra-crosseco.test.ts` | 64 | O/P/Q rules — add chain evidence |

**Upgrade pattern** (use `k1-absent-structured-logging.test.ts` as reference):
```typescript
// BEFORE (shallow):
it("flags injection in resource description", () => {
  const f = run("I3", ctx({...}));
  expect(f.some(x => x.rule_id === "I3")).toBe(true);
});

// AFTER (deep):
it("flags injection in resource description", () => {
  const f = run("I3", ctx({...}));
  expect(f.some(x => x.rule_id === "I3")).toBe(true);
  const finding = f.find(x => x.rule_id === "I3")!;
  // Evidence chain structure
  expect(finding.metadata?.evidence_chain).toBeDefined();
  const chain = finding.metadata!.evidence_chain;
  expect(chain.links.some((l: any) => l.type === "source")).toBe(true);
  expect(chain.links.some((l: any) => l.type === "sink")).toBe(true);
  // Confidence calibration
  expect(chain.confidence).toBeGreaterThan(0.40);
  expect(chain.confidence).toBeLessThan(0.99);
  expect(chain.confidence_factors.length).toBeGreaterThanOrEqual(1);
});
```

**NOTE**: V1 TypedRules store evidence chains in `finding.metadata.evidence_chain` (not `finding.chain`). V2 rules use `RuleResult.chain` which the adapter converts to `metadata.evidence_chain`. Check both patterns.

**Parallelizable**: Split into 3 agents:
- Agent A: category-code-analysis + category-description-analysis + category-schema-analysis (104 tests)
- Agent B: category-protocol-surface + category-ai-runtime-protocol-edge + category-ecosystem-adversarial (79 tests)
- Agent C: category-threat-compliance-supply + category-dependency-behavioral + category-privacy-infra-crosseco (154 tests)

### 4.2 — Upgrade Shallow Tests (Batch B: engine.test.ts)

**File**: `__tests__/engine.test.ts` — 280 tests, 6684 lines

This is the largest test file. NOT all 280 tests need chain upgrades — many test engine mechanics (rule loading, error isolation, context mapping) rather than individual rule detection. Strategy:

1. **Identify rule-specific detection tests** — tests that check for specific rule_id findings
2. **Add chain assertions ONLY to detection tests** — don't touch engine infrastructure tests
3. **Add confidence ordering tests** — where the same rule fires on different inputs, assert higher confidence for clearer violations
4. Estimated: ~120 of 280 tests need chain assertion upgrades

### 4.3 — Formalized Benign Corpus

**New file**: `__tests__/benign-corpus.test.ts`

50+ safe server fixtures that MUST produce zero critical/high findings. Categories:

| Fixture Group | Count | Description |
|---------------|-------|-------------|
| Minimal safe servers | 10 | Simple read-only tools, constrained schemas |
| Real-world safe patterns | 10 | Weather API, calculator, time zone, file reader with restrictions |
| OAuth done right | 5 | PKCE flow, scoped tokens, no implicit grant |
| Proper logging | 5 | Pino/Winston in handlers, structured output |
| Docker hardened | 5 | Non-root, read-only fs, no capabilities |
| Safe descriptions | 5 | Normal tool descriptions, no injection keywords |
| Safe dependencies | 5 | Up-to-date, no CVEs, no typosquats |
| Edge cases that should NOT fire | 5 | Code containing "exec" in variable names, "password" in docs about auth |

Each fixture:
```typescript
it("safe-weather-api: zero critical/high findings", () => {
  const findings = engine.analyze(safeWeatherCtx);
  const critHigh = findings.filter(f => f.severity === "critical" || f.severity === "high");
  expect(critHigh).toEqual([]);  // STRICT: zero, not "few"
});
```

### 4.4 — Enable CI Precision Gate

**File**: `.github/workflows/accuracy.yml` (already exists, schedule disabled)

Changes:
1. Enable schedule: uncomment cron `"0 3 * * 0"` 
2. Add trigger on PR to main: `pull_request: branches: [main]`
3. Ensure the precision threshold assertion works: `passes_layer5_threshold` check
4. Add step summary output for PR review

**File**: `.github/workflows/ci.yml`

Add accuracy check as a CI step (lightweight — runs red-team fixtures, asserts precision >= 80%):
```yaml
accuracy:
  needs: [test]
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - run: pnpm install
    - run: pnpm --filter=red-team run audit --json > accuracy.json
    - run: node -e "const r=require('./accuracy.json'); if(!r.passes_layer5_threshold) process.exit(1)"
```

### 4.5 — Evidence Completeness Validation Script

**New file**: `tools/scripts/validate-evidence-chains.ts`

Script that:
1. Loads all 164 active rules via `loadRules()`
2. For each rule, creates a minimal triggering context (from YAML test_cases.true_positive)
3. Runs the rule
4. Asserts the finding has `metadata.evidence_chain` with at least: 1 source OR 1 sink, confidence > 0.05, at least 1 confidence_factor
5. Reports: rules with chains, rules without chains, percentage coverage
6. Exit code 1 if coverage < 90%

Add as npm script: `"validate:evidence": "tsx tools/scripts/validate-evidence-chains.ts"`

### Phase 4 Verification

- [ ] `pnpm test --filter=analyzer` — all tests pass (existing + upgraded)
- [ ] Evidence chain assertions in all 9 category test files
- [ ] `__tests__/benign-corpus.test.ts` — 50+ fixtures, zero critical/high findings
- [ ] `pnpm validate:evidence` — ≥90% rules produce evidence chains
- [ ] accuracy.yml enabled and passing on current branch
- [ ] Total test count: ~1400+ (up from ~1282)

---

## Phase 5: SKIPPED

---

## Phase 6: Documentation Cleanup

### 6.1 — Fix Rule Count References (177 → 164)

| File | Lines to change | Current | Correct |
|------|----------------|---------|---------|
| `README.md` | 5, 8, 15, 72, 119, 125 | "177 detection rules" | "164 active detection rules (13 retired)" |
| `packages/mcp-sentinel-scanner/README.md` | 3, 11, 34 | "177 detection rules" | "164 active detection rules" |
| `packages/red-team/CLAUDE.md` | 3 | "177 detection rules" | "164 active detection rules" |
| `packages/benchmark/CLAUDE.md` | 44 | "177 rules" | "164 active rules" |
| `packages/scanner/CLAUDE.md` | 13 | "103 detection rules" | "164 active detection rules" |

### 6.2 — Rewrite `agent_docs/technical-roadmap.md`

This file is entirely pre-migration. Stale claims:
- "94 rules (53%) still on regex" → ALL rules are TypedRule implementations
- "~100 rules still on regex-only analysis" → Zero regex remains
- Phase descriptions reference work that is complete

Rewrite to reflect post-Phase-3 reality:
- All 164 rules use AST taint, capability graph, entropy, structural parsing, linguistic scoring
- 13 rules retired with rationale
- Technical debt: remaining shallow tests (being addressed in Phase 4)
- Next priorities: Phase 4 (test overhaul), Phase 6 (docs), then compliance & enterprise

### 6.3 — Clean Up `agent_docs/detection-rules.md`

The Engine Implementation Status tables show `runRegexRule` handlers. Add a header note:
> "**Note:** All 164 active rules have TypedRule implementations in TypeScript. The `runRegexRule` entries below are legacy documentation — TypedRule dispatch takes precedence. Zero YAML regex patterns remain in active rules."

Update the table for rules migrated in Batch 1-4 to show their actual technique (AST taint, structural, Noisy-OR, etc.) instead of `runRegexRule`.

### 6.4 — Update Package CLAUDE.md Files

- `packages/analyzer/CLAUDE.md` — Move legacy handler table to "Deprecated" section; update rule count
- `packages/mcp-sentinel-scanner/CLAUDE.md` — Already partially updated; verify consistency
- `packages/scorer/CLAUDE.md` — Verify rule count references

### 6.5 — Update Test Counts in Product Milestones

After Phase 4 completes, update `agent_docs/product-milestones.md`:
- Test count from "1051 tests" → actual count after Phase 4
- Phase statuses: Phase 3 COMPLETE, Phase 4 COMPLETE, Phase 5 SKIPPED

### Phase 6 Verification

- [ ] `grep -r '177' README.md packages/*/README.md packages/*/CLAUDE.md agent_docs/` returns zero stale hits
- [ ] `grep -r '103 detection' packages/scanner/` returns zero hits
- [ ] `agent_docs/technical-roadmap.md` reflects post-migration reality
- [ ] All package CLAUDE.md files have consistent rule counts

---

## Reusable Infrastructure (DO NOT rebuild)

| Module | Path | Lines |
|---|---|---|
| AST Taint Engine | `taint-ast.ts` | 821 |
| Lightweight Taint | `taint.ts` | 676 |
| Capability Graph | `capability-graph.ts` | 761 |
| Module Graph | `module-graph.ts` | 826 |
| Entropy Analysis | `entropy.ts` | 449 |
| Similarity | `similarity.ts` | 477 |
| Evidence Builder | `evidence.ts` | 80 |
| Confidence Signals | `confidence-signals.ts` | ~200 |
| Schema Inference | `schema-inference.ts` | ~300 |

---

## Execution Order

1. **Phase 4.1** — Upgrade category test files (3 parallel agents)
2. **Phase 4.2** — Upgrade engine.test.ts detection tests
3. **Phase 4.3** — Create benign corpus test file
4. **Phase 4.4** — Enable CI precision gate
5. **Phase 4.5** — Create evidence validation script
6. **Phase 6.1-6.4** — Documentation fixes (can run in parallel with Phase 4.4-4.5)
7. **Phase 6.5** — Final count updates after Phase 4 completes

## Final Verification Checklist

1. `pnpm typecheck` — zero errors
2. `pnpm test` — all tests pass (existing + upgraded + benign corpus)
3. `pnpm validate:evidence` — ≥90% rules produce evidence chains
4. accuracy.yml runs and passes on branch
5. `grep -r '177' README.md packages/*/README.md packages/*/CLAUDE.md agent_docs/` — zero stale hits
6. `grep -r 'runRegexRule' agent_docs/detection-rules.md` — clarified with TypedRule precedence note
7. Retired rules remain `enabled: false` in YAML with rationale
8. Total test count ≥1400
