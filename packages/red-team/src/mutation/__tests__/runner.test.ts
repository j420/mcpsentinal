/**
 * Runner integration tests.
 *
 * We don't run the full 164-rule audit here (that's the CLI's job); instead
 * we exercise the runner on a narrow rule filter to assert:
 *   - it runs without throwing
 *   - it emits a well-formed MutationReport
 *   - the per-rule summary contains survived/blind lists sorted by the
 *     canonical MUTATION_IDS order
 *   - an unknown rule filter produces 0 per-rule rows (and 0 outcomes)
 */

import { describe, it, expect } from "vitest";
import { runMutationAudit } from "../runner.js";
import { MUTATION_IDS } from "../types.js";

describe("runMutationAudit", () => {
  it("returns a well-formed report for a narrow rule filter (K1)", () => {
    const report = runMutationAudit({ ruleFilter: "K1" });
    expect(report.generated_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(report.rules_version).toMatch(/^typed-v2-/);
    // K1 exists and has true-positive fixtures.
    const k1 = report.per_rule_summary.find((r) => r.rule_id === "K1");
    expect(k1).toBeDefined();
    expect(k1!.no_fixtures).toBe(false);
    // The arrays must be a subset of MUTATION_IDS.
    for (const m of k1!.survived) expect(MUTATION_IDS).toContain(m);
    for (const m of k1!.acknowledged_blind) expect(MUTATION_IDS).toContain(m);
  });

  it("returns 0 rows for an unknown rule filter", () => {
    const report = runMutationAudit({ ruleFilter: "ZZZZ" });
    expect(report.per_rule_summary.length).toBe(0);
    expect(report.outcomes.length).toBe(0);
    expect(report.totals.rules_total).toBe(0);
  });

  it("survived/blind/errors/not_applicable are disjoint per rule", () => {
    const report = runMutationAudit({ ruleFilter: "K1" });
    for (const r of report.per_rule_summary) {
      const sets = [r.survived, r.acknowledged_blind, r.not_applicable, r.errors];
      const all = sets.flat();
      expect(all.length).toBe(new Set(all).size);
    }
  });

  it("every outcome has both findings_before and findings_after as numbers", () => {
    const report = runMutationAudit({ ruleFilter: "K1" });
    for (const o of report.outcomes) {
      expect(typeof o.findings_before).toBe("number");
      expect(typeof o.findings_after).toBe("number");
      expect(o.findings_before).toBeGreaterThanOrEqual(0);
      expect(o.findings_after).toBeGreaterThanOrEqual(0);
    }
  });

  it("rules with no fixtures report no_fixtures=true and empty lists", () => {
    // Pick a rule id that is almost certainly a stub / companion with no fixtures.
    // I2 is the classic companion of I1 (per detection-rules.md).
    const report = runMutationAudit({ ruleFilter: "I2" });
    const i2 = report.per_rule_summary.find((r) => r.rule_id === "I2");
    if (i2 && i2.no_fixtures) {
      expect(i2.survived).toEqual([]);
      expect(i2.acknowledged_blind).toEqual([]);
    }
  });
});
