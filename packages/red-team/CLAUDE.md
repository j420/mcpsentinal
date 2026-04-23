# Package: red-team

**Purpose:** Adversarial validation for MCP Sentinel. Three subsystems:
1. **Accuracy runner** — precision/recall audit for all 164 active detection rules across 17 categories (13 retired). Enforces the Layer 5 quality gate (precision ≥ 80%).
2. **Mutation suite (Phase 2.2)** — 8 TS-AST mutations × 163 rules; always-fail parity guard against CHARTER `mutations_survived` frontmatter.
3. **CVE replay corpus (Phase 4)** — 22 falsifiable cases (16 CVEs + 6 research attacks) that each prove specific detection rules catch specific real-world attacks. Harness contract at `docs/standards/cve-replay-corpus-spec.md`.

## Key Files

**Accuracy runner:**
- `src/runner.ts` — `AccuracyRunner` class (loads rules, runs fixtures, computes metrics)
- `src/types.ts` — `RuleFixture`, `RuleFixtureSet`, `RuleAccuracy`, `AccuracyReport`, `CategoryAccuracy`
- `src/reporter.ts` — Text, JSON, and HTML report formatters
- `src/cli.ts` — `pnpm red-team` CLI entry point
- `src/fixtures/` — 17 category fixture files (A through Q), ~900 fixtures total
- `src/fixtures/index.ts` — `ALL_FIXTURES` aggregate + `getFixturesForRule()` lookup
- `src/accuracy/` — dashboard module (reads `rules/accuracy-targets.yaml`, emits `docs/accuracy/latest.json` + `trend.md`)

**Mutation suite (Phase 2.2):**
- `src/mutation/` — 8 AST mutations (rename-danger-symbol, split-string-literal, unicode-homoglyph-identifier, base64-wrap-payload, intermediate-variable, add-noop-conditional, swap-option-shape, reorder-object-properties) + runner + CLI
- Baseline at `docs/mutations/latest.{json,md}`

**CVE replay corpus (Phase 4):**
- `src/cve-corpus/types.ts` — `CVEReplayCase`, `CVECaseResult`, `CVECorpusReport`
- `src/cve-corpus/registry.ts` — `registerCVECase()` + ID format + duplicate guard
- `src/cve-corpus/loader.ts` — side-effect import driver + CVE manifest loader
- `src/cve-corpus/runner.ts` — `CVECorpusRunner` with 4 assertion classes (manifest membership, expected rules fire, forbidden rules silence, patched fixture silence)
- `src/cve-corpus/reporter.ts` — text/JSON/markdown formatters
- `src/cve-corpus/coverage-doc-generator.ts` — emits `docs/cve-coverage.md`
- `src/cve-corpus/cli.ts` — `pnpm --filter=@mcp-sentinel/red-team cve-corpus`
- `src/cve-corpus/cases/cve/*.ts` — 16 CVE cases
- `src/cve-corpus/cases/research/*.ts` — 6 research-attack replays
- `src/cve-corpus/cases/__example__/` — reference synthetic case (registered only in tests)

## Fixture Format

```typescript
interface RuleFixture {
  description: string;
  context: Partial<AnalysisContext> & { server: AnalysisContext["server"] };
  expect_finding: boolean;   // true = should fire, false = must not fire
  evidence_contains?: string; // verify finding is for the right reason
  kind: "true_positive" | "true_negative" | "edge_case";
  threat_ref?: string;        // OWASP or MITRE reference
}
```

Every rule requires minimum 2 true positives + 2 true negatives (per `agent_docs/detection-rules.md`).

## Metrics

| Metric | Formula | What It Measures |
|--------|---------|-----------------|
| Precision | TN_correct / all_negatives | False alarm avoidance |
| Recall | TP_correct / all_positives | Catch rate |
| Layer 5 threshold | overall_precision >= 0.80 | Quality gate |

## CLI Usage

```bash
# Accuracy runner
pnpm red-team                       # Run all fixtures (text output)
pnpm red-team --json                # JSON output for CI
pnpm red-team --html                # HTML report for dashboards
pnpm red-team --rule A1             # Test single rule
pnpm red-team --category C          # Test single category
pnpm red-team --fail-fast           # Exit on first failure

# CVE replay corpus (Phase 4)
pnpm --filter=@mcp-sentinel/red-team cve-corpus              # Run all cases (text output)
pnpm --filter=@mcp-sentinel/red-team cve-corpus:report       # Markdown report
pnpm --filter=@mcp-sentinel/red-team cve-corpus:coverage     # Regenerate docs/cve-coverage.md
```

Accuracy runner exit code = 1 if `total_failed > 0` OR precision < 80%. CVE corpus exit code = 1 on any case failure OR any cve-kind id missing from `docs/cve-manifest.json`.

## Fixture Categories

| Category | Rules | Fixtures |
|----------|-------|----------|
| A (description) | A1–A9 | ~70 |
| B (schema) | B1–B7 | ~35 |
| C (code) | C1–C16 | ~120 |
| D (dependency) | D1–D7 | ~35 |
| E (behavioral) | E1–E4 | ~12 |
| F (ecosystem) | F1–F7 | ~30 |
| G (adversarial) | G1–G7 | ~35 |
| H (2026 surface) | H1–H3 | ~20 |
| I (protocol) | I1–I16 | ~70 |
| J (threat intel) | J1–J7 | ~42 |
| K (compliance) | K1–K20 | ~60 |
| L (supply chain) | L1–L15 | ~75 |
| M (AI runtime) | M1–M9 | ~37 |
| N (protocol edge) | N1–N15 | ~75 |
| O (data privacy) | O1–O10 | ~50 |
| P (infrastructure) | P1–P10 | ~50 |
| Q (cross-ecosystem) | Q1–Q15 | ~81 |

## Pipeline Integration

Runs weekly via `.github/workflows/accuracy.yml` (Sundays 03:00 UTC, after crawl).
Manual dispatch available for on-demand audits. Fails CI if precision drops below 80%.

## Adding a Fixture

1. Open the fixture file for the rule's category (e.g., `src/fixtures/c-code.ts` for C-rules)
2. Add a `RuleFixture` to the array for the target rule
3. Run `pnpm red-team --rule <id>` to verify
4. Ensure both true_positive and true_negative cases exist

## Running Tests
```bash
pnpm test --filter=@mcp-sentinel/red-team
```

## What NOT to Do
- Do NOT lower the Layer 5 threshold below 0.80 without product approval
- Do NOT remove fixtures — add new ones instead to improve coverage
- Do NOT add LLM-based fixture evaluation — all analysis is deterministic (ADR-006)
- Do NOT modify `AccuracyRunner` to skip failed rules — failures must be surfaced
- Do NOT add inline SQL — no DB access in this package
