# Package: red-team

**Purpose:** Precision/recall accuracy auditing for all 177 detection rules across 17 categories. Runs rule fixtures through the analyzer engine, computes per-rule metrics, and enforces the Layer 5 quality gate (precision >= 80%).

## Key Files
- `src/runner.ts` — `AccuracyRunner` class (loads rules, runs fixtures, computes metrics)
- `src/types.ts` — `RuleFixture`, `RuleFixtureSet`, `RuleAccuracy`, `AccuracyReport`, `CategoryAccuracy`
- `src/reporter.ts` — Text, JSON, and HTML report formatters
- `src/cli.ts` — `pnpm red-team` CLI entry point
- `src/fixtures/` — 17 category fixture files (A through Q), ~900 fixtures total
- `src/fixtures/index.ts` — `ALL_FIXTURES` aggregate + `getFixturesForRule()` lookup
- `src/__tests__/` — 49 tests

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
pnpm red-team                       # Run all fixtures (text output)
pnpm red-team --json                # JSON output for CI
pnpm red-team --html                # HTML report for dashboards
pnpm red-team --rule A1             # Test single rule
pnpm red-team --category C          # Test single category
pnpm red-team --fail-fast           # Exit on first failure
```

Exit code = 1 if `total_failed > 0` OR precision < 80%.

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
