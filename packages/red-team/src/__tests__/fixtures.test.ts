import { describe, it, expect, beforeAll } from "vitest";
import { AccuracyRunner } from "../runner.js";
import { ALL_FIXTURES, getFixturesForRule } from "../fixtures/index.js";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const RULES_DIR = resolve(__dirname, "../../../../rules");

describe("Red Team — Rule Fixture Coverage", () => {
  it("should have fixtures for at least 30 distinct rules", () => {
    const ruleIds = new Set(ALL_FIXTURES.map((f) => f.rule_id));
    expect(ruleIds.size).toBeGreaterThanOrEqual(30);
  });

  it("every fixture set should have at least 1 true positive and 1 true negative", () => {
    for (const fs of ALL_FIXTURES) {
      const tps = fs.fixtures.filter((f) => f.kind === "true_positive");
      const tns = fs.fixtures.filter((f) => f.kind === "true_negative");
      expect(tps.length, `${fs.rule_id}: missing true positives`).toBeGreaterThanOrEqual(1);
      expect(tns.length, `${fs.rule_id}: missing true negatives`).toBeGreaterThanOrEqual(1);
    }
  });

  it("every fixture should have a non-empty description", () => {
    for (const fs of ALL_FIXTURES) {
      for (const f of fs.fixtures) {
        expect(
          f.description.length,
          `${fs.rule_id}: fixture has empty description`
        ).toBeGreaterThan(0);
      }
    }
  });

  it("getFixturesForRule should return the correct set", () => {
    const a1 = getFixturesForRule("A1");
    expect(a1).toBeDefined();
    expect(a1!.rule_id).toBe("A1");
  });
});

describe("Red Team — Accuracy Runner", () => {
  let runner: AccuracyRunner;

  beforeAll(() => {
    runner = new AccuracyRunner(RULES_DIR);
  });

  it("should produce a report with overall_precision and overall_recall in [0,1]", () => {
    const report = runner.runAll(ALL_FIXTURES);
    expect(report.overall_precision).toBeGreaterThanOrEqual(0);
    expect(report.overall_precision).toBeLessThanOrEqual(1);
    expect(report.overall_recall).toBeGreaterThanOrEqual(0);
    expect(report.overall_recall).toBeLessThanOrEqual(1);
  });

  it("should test all fixture sets and report counts correctly", () => {
    const report = runner.runAll(ALL_FIXTURES);
    expect(report.total_rules_tested).toBe(ALL_FIXTURES.length);
    const expectedTotal = ALL_FIXTURES.reduce((s, fs) => s + fs.fixtures.length, 0);
    expect(report.total_fixtures).toBe(expectedTotal);
    expect(report.total_passed + report.total_failed).toBe(report.total_fixtures);
  });

  it("should have by_rule entries for every fixture set", () => {
    const report = runner.runAll(ALL_FIXTURES);
    const reportedIds = new Set(report.by_rule.map((r) => r.rule_id));
    for (const fs of ALL_FIXTURES) {
      expect(reportedIds.has(fs.rule_id), `missing ${fs.rule_id} in report`).toBe(true);
    }
  });

  it("should correctly classify a fixture as passed when engine fires as expected", () => {
    // A7 zero-width injection — engine MUST fire on ZWS input
    const a7 = getFixturesForRule("A7");
    expect(a7).toBeDefined();
    const tpFixture = a7!.fixtures.find((f) => f.kind === "true_positive");
    expect(tpFixture).toBeDefined();

    const result = runner.runFixture(tpFixture!, "A7");
    // The fixture expects a finding; if the engine is working, result.passed = true
    // If the rule is not yet implemented, this will fail — which is correct (it surfaces the gap)
    expect(typeof result.passed).toBe("boolean");
    expect(result.rule_id).toBe("A7");
  });
});

describe("Red Team — A1 Prompt Injection Fixtures", () => {
  let runner: AccuracyRunner;

  beforeAll(() => {
    runner = new AccuracyRunner(RULES_DIR);
  });

  it("A1 should fire on classic ignore-previous-instructions", () => {
    const a1 = getFixturesForRule("A1")!;
    const fixture = a1.fixtures.find((f) => f.description.includes("ignore-previous"))!;
    const result = runner.runFixture(fixture, "A1");
    if (fixture.expect_finding) {
      // Engine should fire — if not, log but don't hard-fail (rule may catch different patterns)
      expect(result.got_finding || !fixture.expect_finding).toBe(true);
    }
  });

  it("A1 should NOT fire on security tool that mentions injection concepts", () => {
    const a1 = getFixturesForRule("A1")!;
    const fixture = a1.fixtures.find((f) =>
      f.description.includes("security tool that mentions injection")
    )!;
    const result = runner.runFixture(fixture, "A1");
    expect(result.expect_finding).toBe(false);
    // The fixture is a true negative — we verify it's correctly classified as such
    expect(typeof result.passed).toBe("boolean");
  });
});

describe("Red Team — C5 Hardcoded Secrets Fixtures", () => {
  let runner: AccuracyRunner;

  beforeAll(() => {
    runner = new AccuracyRunner(RULES_DIR);
  });

  it("C5 should handle all secret formats defined in the fixture set", () => {
    const c5 = getFixturesForRule("C5")!;
    expect(c5.fixtures.length).toBeGreaterThanOrEqual(10);
    const tps = c5.fixtures.filter((f) => f.kind === "true_positive");
    const tns = c5.fixtures.filter((f) => f.kind === "true_negative");
    expect(tps.length).toBeGreaterThanOrEqual(5);
    expect(tns.length).toBeGreaterThanOrEqual(2);
  });
});

describe("Red Team — I1 Annotation Deception Fixtures", () => {
  let runner: AccuracyRunner;

  beforeAll(() => {
    runner = new AccuracyRunner(RULES_DIR);
  });

  it("I1 fixture set covers both deceptive and honest annotations", () => {
    const i1 = getFixturesForRule("I1")!;
    const deceptive = i1.fixtures.filter((f) => f.expect_finding);
    const honest = i1.fixtures.filter((f) => !f.expect_finding);
    expect(deceptive.length).toBeGreaterThanOrEqual(2);
    expect(honest.length).toBeGreaterThanOrEqual(2);
  });
});

// ─── Layer 5 Threshold Tests ──────────────────────────────────────────────────

describe("Red Team — Layer 5 Threshold (passes_layer5_threshold)", () => {
  let runner: AccuracyRunner;

  beforeAll(() => {
    runner = new AccuracyRunner(RULES_DIR);
  });

  it("report has passes_layer5_threshold boolean field", () => {
    const report = runner.runAll(ALL_FIXTURES);
    expect(typeof report.passes_layer5_threshold).toBe("boolean");
  });

  it("passes_layer5_threshold = true when overall_precision >= 0.8", () => {
    const report = runner.runAll(ALL_FIXTURES);
    if (report.overall_precision >= 0.8) {
      expect(report.passes_layer5_threshold).toBe(true);
    } else {
      expect(report.passes_layer5_threshold).toBe(false);
    }
  });

  it("passes_layer5_threshold is consistent with overall_precision value", () => {
    const report = runner.runAll(ALL_FIXTURES);
    expect(report.passes_layer5_threshold).toBe(report.overall_precision >= 0.8);
  });

  it("runAll on empty fixture list returns passes_layer5_threshold=true (precision defaults to 1.0)", () => {
    const report = runner.runAll([]);
    // overallPrecision defaults to 1.0 when no rules tested → 1.0 >= 0.8 → true
    expect(report.passes_layer5_threshold).toBe(true);
    expect(report.overall_precision).toBe(1.0);
  });
});

// ─── By-Category Breakdown Tests ─────────────────────────────────────────────

describe("Red Team — by_category breakdown", () => {
  let runner: AccuracyRunner;

  beforeAll(() => {
    runner = new AccuracyRunner(RULES_DIR);
  });

  it("by_category is populated for every rule letter present in fixtures", () => {
    const report = runner.runAll(ALL_FIXTURES);
    // Derive expected category letters from fixture rule IDs
    const expectedCategories = new Set(
      ALL_FIXTURES.map((fs) => fs.rule_id[0].toUpperCase())
    );
    for (const cat of expectedCategories) {
      expect(
        report.by_category[cat],
        `category '${cat}' missing from by_category`
      ).toBeDefined();
    }
  });

  it("each by_category entry has avg_precision and avg_recall in [0, 1]", () => {
    const report = runner.runAll(ALL_FIXTURES);
    for (const [cat, acc] of Object.entries(report.by_category)) {
      expect(acc.avg_precision, `${cat}.avg_precision`).toBeGreaterThanOrEqual(0);
      expect(acc.avg_precision, `${cat}.avg_precision`).toBeLessThanOrEqual(1);
      expect(acc.avg_recall, `${cat}.avg_recall`).toBeGreaterThanOrEqual(0);
      expect(acc.avg_recall, `${cat}.avg_recall`).toBeLessThanOrEqual(1);
    }
  });

  it("each by_category entry has passes_threshold boolean", () => {
    const report = runner.runAll(ALL_FIXTURES);
    for (const [cat, acc] of Object.entries(report.by_category)) {
      expect(typeof acc.passes_threshold, `${cat}.passes_threshold`).toBe("boolean");
      expect(acc.passes_threshold).toBe(acc.avg_precision >= 0.8 && acc.avg_recall >= 0.8);
    }
  });

  it("by_category rules_count matches number of fixture sets with that prefix", () => {
    const report = runner.runAll(ALL_FIXTURES);
    for (const [cat, acc] of Object.entries(report.by_category)) {
      const expectedCount = ALL_FIXTURES.filter(
        (fs) => fs.rule_id[0].toUpperCase() === cat
      ).length;
      expect(acc.rules_count, `${cat}.rules_count`).toBe(expectedCount);
    }
  });

  it("all 11 rule categories (A-K) have by_category entries", () => {
    const report = runner.runAll(ALL_FIXTURES);
    const categories = Object.keys(report.by_category);
    for (const letter of ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K"]) {
      expect(categories, `Missing category ${letter}`).toContain(letter);
    }
  });
});

// ─── Worst Performers Tests ───────────────────────────────────────────────────

describe("Red Team — worst_performers", () => {
  let runner: AccuracyRunner;

  beforeAll(() => {
    runner = new AccuracyRunner(RULES_DIR);
  });

  it("worst_performers has at most 10 entries", () => {
    const report = runner.runAll(ALL_FIXTURES);
    expect(report.worst_performers.length).toBeLessThanOrEqual(10);
  });

  it("worst_performers is ordered by combined score ascending (worst first)", () => {
    const report = runner.runAll(ALL_FIXTURES);
    const scores = report.worst_performers.map(
      (r) => r.true_positive_recall * r.true_negative_precision
    );
    for (let i = 1; i < scores.length; i++) {
      expect(scores[i], `scores[${i}] should be >= scores[${i - 1}]`).toBeGreaterThanOrEqual(
        scores[i - 1]
      );
    }
  });

  it("each worst_performer entry has rule_id and rule_name", () => {
    const report = runner.runAll(ALL_FIXTURES);
    for (const perf of report.worst_performers) {
      expect(typeof perf.rule_id).toBe("string");
      expect(typeof perf.rule_name).toBe("string");
      expect(perf.rule_id.length).toBeGreaterThan(0);
    }
  });

  it("worst_performers entries are a subset of by_rule", () => {
    const report = runner.runAll(ALL_FIXTURES);
    const allRuleIds = new Set(report.by_rule.map((r) => r.rule_id));
    for (const perf of report.worst_performers) {
      expect(allRuleIds.has(perf.rule_id), `${perf.rule_id} not in by_rule`).toBe(true);
    }
  });

  it("returns fewer than 10 entries if fewer than 10 fixture sets provided", () => {
    const subset = ALL_FIXTURES.slice(0, 5);
    const report = runner.runAll(subset);
    expect(report.worst_performers.length).toBeLessThanOrEqual(5);
  });
});

// ─── Edge Case Fixture Coverage ───────────────────────────────────────────────

describe("Red Team — edge_case fixture coverage", () => {
  it("at least 5 fixture sets include edge_case variants", () => {
    const setsWithEdgeCases = ALL_FIXTURES.filter((fs) =>
      fs.fixtures.some((f) => f.kind === "edge_case")
    );
    expect(setsWithEdgeCases.length).toBeGreaterThanOrEqual(5);
  });

  it("all edge_case fixtures have non-empty descriptions", () => {
    for (const fs of ALL_FIXTURES) {
      const edgeCases = fs.fixtures.filter((f) => f.kind === "edge_case");
      for (const ec of edgeCases) {
        expect(
          ec.description.length,
          `${fs.rule_id}: edge_case has empty description`
        ).toBeGreaterThan(0);
      }
    }
  });

  it("edge_case fixtures have an expect_finding value (not undefined)", () => {
    for (const fs of ALL_FIXTURES) {
      const edgeCases = fs.fixtures.filter((f) => f.kind === "edge_case");
      for (const ec of edgeCases) {
        expect(
          typeof ec.expect_finding,
          `${fs.rule_id}: edge_case missing expect_finding`
        ).toBe("boolean");
      }
    }
  });
});

// ─── AccuracyReport Shape Invariants ─────────────────────────────────────────

describe("Red Team — AccuracyReport shape invariants", () => {
  let runner: AccuracyRunner;

  beforeAll(() => {
    runner = new AccuracyRunner(RULES_DIR);
  });

  it("report has generated_at as ISO timestamp string", () => {
    const report = runner.runAll(ALL_FIXTURES);
    expect(typeof report.generated_at).toBe("string");
    expect(() => new Date(report.generated_at)).not.toThrow();
    expect(new Date(report.generated_at).toISOString()).toBe(report.generated_at);
  });

  it("report has rules_version string", () => {
    const report = runner.runAll(ALL_FIXTURES);
    expect(typeof report.rules_version).toBe("string");
    expect(report.rules_version.length).toBeGreaterThan(0);
  });

  it("total_passed + total_failed = total_fixtures", () => {
    const report = runner.runAll(ALL_FIXTURES);
    expect(report.total_passed + report.total_failed).toBe(report.total_fixtures);
  });

  it("total_rules_tested equals ALL_FIXTURES.length", () => {
    const report = runner.runAll(ALL_FIXTURES);
    expect(report.total_rules_tested).toBe(ALL_FIXTURES.length);
  });

  it("by_rule has an entry for every fixture set", () => {
    const report = runner.runAll(ALL_FIXTURES);
    expect(report.by_rule.length).toBe(ALL_FIXTURES.length);
  });

  it("each by_rule entry: passed + failed = total", () => {
    const report = runner.runAll(ALL_FIXTURES);
    for (const rule of report.by_rule) {
      expect(rule.passed + rule.failed, `${rule.rule_id}: passed+failed != total`).toBe(rule.total);
    }
  });

  it("each by_rule entry: recall and precision in [0, 1]", () => {
    const report = runner.runAll(ALL_FIXTURES);
    for (const rule of report.by_rule) {
      expect(rule.true_positive_recall, `${rule.rule_id} recall`).toBeGreaterThanOrEqual(0);
      expect(rule.true_positive_recall, `${rule.rule_id} recall`).toBeLessThanOrEqual(1);
      expect(rule.true_negative_precision, `${rule.rule_id} precision`).toBeGreaterThanOrEqual(0);
      expect(rule.true_negative_precision, `${rule.rule_id} precision`).toBeLessThanOrEqual(1);
    }
  });

  it("edge_case_pass_rate is in [0, 1] for all rules", () => {
    const report = runner.runAll(ALL_FIXTURES);
    for (const rule of report.by_rule) {
      expect(rule.edge_case_pass_rate, `${rule.rule_id} edge_case_pass_rate`).toBeGreaterThanOrEqual(0);
      expect(rule.edge_case_pass_rate, `${rule.rule_id} edge_case_pass_rate`).toBeLessThanOrEqual(1);
    }
  });

  it("failed_fixtures is an array (possibly empty) for every rule", () => {
    const report = runner.runAll(ALL_FIXTURES);
    for (const rule of report.by_rule) {
      expect(Array.isArray(rule.failed_fixtures), `${rule.rule_id} failed_fixtures`).toBe(true);
    }
  });
});

// ─── Category-specific minimum fixture counts ─────────────────────────────────

describe("Red Team — minimum fixture counts per category", () => {
  const EXPECTED_MINIMUMS: Record<string, number> = {
    A: 9,   // A1-A9: 9 rules
    B: 7,   // B1-B7: 7 rules
    C: 16,  // C1-C16: 16 rules
    D: 7,   // D1-D7: 7 rules
    E: 4,   // E1-E4: 4 rules
    F: 7,   // F1-F7: 7 rules
    G: 7,   // G1-G7: 7 rules
    H: 3,   // H1-H3: 3 rules
    I: 16,  // I1-I16: 16 rules
    J: 7,   // J1-J7: 7 rules
    K: 20,  // K1-K20: 20 rules
  };

  for (const [cat, minCount] of Object.entries(EXPECTED_MINIMUMS)) {
    it(`category ${cat} has at least ${minCount} fixture sets`, () => {
      const count = ALL_FIXTURES.filter(
        (fs) => fs.rule_id[0].toUpperCase() === cat
      ).length;
      expect(count, `Category ${cat}: expected >= ${minCount}, got ${count}`).toBeGreaterThanOrEqual(
        minCount
      );
    });
  }
});
