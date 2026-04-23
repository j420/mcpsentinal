/**
 * Tests for the accuracy dashboard module.
 *
 * Four tests, per the chunk 2.4 brief:
 *   (a) parses rules/accuracy-targets.yaml
 *   (b) joins per-rule measurements with declared targets
 *   (c) detects regressions vs a prior baseline
 *   (d) emits a latest.json that round-trips through JSON.parse
 */
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  loadAccuracyTargets,
  resetTargetsCache,
  getTargetFor,
} from "../target-loader.js";
import {
  buildDashboard,
  renderLatestJson,
  renderTrendMarkdown,
  writeDashboardArtefacts,
  readPriorSnapshot,
  type DashboardSnapshot,
} from "../dashboard.js";
import type { RuleFixtureSet, AccuracyReport, RuleAccuracy } from "../../types.js";
import { AccuracyRunner } from "../../runner.js";

// A minimal, deterministic stub AccuracyRunner — it doesn't invoke the real
// analyzer engine. Instead it returns pre-canned RuleAccuracy rows based on
// the fixture sets provided. This keeps the dashboard tests fast, hermetic,
// and independent of all 164 detection rules.
class StubRunner extends AccuracyRunner {
  private overrides: Map<string, RuleAccuracy>;

  constructor(overrides: Map<string, RuleAccuracy>) {
    super();
    this.overrides = overrides;
  }

  override runAll(fixtureSets: RuleFixtureSet[]): AccuracyReport {
    const byRule = fixtureSets.map(fs => {
      const o = this.overrides.get(fs.rule_id);
      if (o) return o;
      // Default: perfect metrics with fixture shape matching
      const tps = fs.fixtures.filter(x => x.kind === "true_positive" && x.expect_finding).length;
      const tns = fs.fixtures.filter(x => x.kind === "true_negative" && !x.expect_finding).length;
      return {
        rule_id: fs.rule_id,
        rule_name: fs.rule_name,
        total: fs.fixtures.length,
        passed: fs.fixtures.length,
        failed: 0,
        true_positive_recall: tps > 0 ? 1.0 : 1.0,
        true_negative_precision: tns > 0 ? 1.0 : 1.0,
        edge_case_pass_rate: 1.0,
        failed_fixtures: [],
      } satisfies RuleAccuracy;
    });

    const avg = (sel: (r: RuleAccuracy) => number) =>
      byRule.length > 0 ? byRule.reduce((s, r) => s + sel(r), 0) / byRule.length : 1.0;

    return {
      generated_at: "2026-04-22T00:00:00.000Z",
      rules_version: "test-1.0",
      total_rules_tested: byRule.length,
      total_fixtures: byRule.reduce((s, r) => s + r.total, 0),
      total_passed: byRule.reduce((s, r) => s + r.passed, 0),
      total_failed: byRule.reduce((s, r) => s + r.failed, 0),
      overall_precision: avg(r => r.true_negative_precision),
      overall_recall: avg(r => r.true_positive_recall),
      passes_layer5_threshold: avg(r => r.true_negative_precision) >= 0.8,
      by_category: {},
      by_rule: byRule,
      worst_performers: [],
    };
  }
}

const DEMO_FIXTURES: RuleFixtureSet[] = [
  {
    rule_id: "A1",
    rule_name: "Prompt Injection in Tool Description",
    fixtures: [
      {
        description: "ignore previous instructions",
        context: { server: { id: "s", name: "s", description: "", github_url: null } },
        expect_finding: true,
        kind: "true_positive",
      },
      {
        description: "legitimate description",
        context: { server: { id: "s", name: "s", description: "", github_url: null } },
        expect_finding: false,
        kind: "true_negative",
      },
    ],
  },
  {
    rule_id: "C1",
    rule_name: "Command Injection",
    fixtures: [
      {
        description: "exec user input",
        context: { server: { id: "s", name: "s", description: "", github_url: null } },
        expect_finding: true,
        kind: "true_positive",
      },
      {
        description: "execFile with array",
        context: { server: { id: "s", name: "s", description: "", github_url: null } },
        expect_finding: false,
        kind: "true_negative",
      },
    ],
  },
];

describe("accuracy/target-loader", () => {
  beforeEach(() => resetTargetsCache());

  it("(a) parses rules/accuracy-targets.yaml with 163 active rule entries", () => {
    // Use the real manifest committed at the repo root. 163 = 164 active -
    // 1 (I14, disabled in chunk 2.1-bugfix pending a TypedRuleV2 impl).
    const targets = loadAccuracyTargets();
    expect(targets.version).toBe(1);
    expect(targets.default.target_precision).toBeGreaterThan(0);
    expect(Object.keys(targets.rules).length).toBe(163);

    // A1 must exist and have non-empty rationale.
    const a1 = getTargetFor("A1", targets);
    expect(a1.target_precision).toBeGreaterThan(0);
    expect(a1.rationale.length).toBeGreaterThan(10);

    // F2 is a companion stub — target_recall must be null (N/A).
    const f2 = getTargetFor("F2", targets);
    expect(f2.target_recall).toBeNull();
    expect(f2.target_precision).toBe(1.0);
  });
});

describe("accuracy/dashboard", () => {
  beforeEach(() => resetTargetsCache());

  it("(b) joins measured per-rule metrics with declared targets and computes passes", () => {
    // Override A1 with a below-target precision to force a failure.
    const overrides = new Map<string, RuleAccuracy>([
      [
        "A1",
        {
          rule_id: "A1",
          rule_name: "Prompt Injection",
          total: 2,
          passed: 1,
          failed: 1,
          true_positive_recall: 1.0,
          true_negative_precision: 0.5, // below 0.90 target
          edge_case_pass_rate: 1.0,
          failed_fixtures: [
            {
              rule_id: "A1",
              fixture_description: "legitimate description",
              kind: "true_negative",
              expect_finding: false,
              got_finding: true,
              passed: false,
              elapsed_ms: 1,
            },
          ],
        },
      ],
    ]);

    const { snapshot } = buildDashboard({
      runner: new StubRunner(overrides),
      fixtures: DEMO_FIXTURES,
      priorSnapshot: null,
    });

    const a1 = snapshot.rules.find(r => r.rule_id === "A1")!;
    expect(a1).toBeDefined();
    expect(a1.measured_precision).toBe(0.5);
    expect(a1.target_precision).toBeGreaterThanOrEqual(0.85);
    expect(a1.passes_precision).toBe(false);
    expect(a1.passes).toBe(false);
    // Delta is 0 because no prior snapshot.
    expect(a1.delta_precision).toBe(0);
    expect(a1.baseline_delta).toBe(true);

    const c1 = snapshot.rules.find(r => r.rule_id === "C1")!;
    expect(c1.passes).toBe(true);

    // Aggregate surface
    expect(snapshot.aggregate.rule_count).toBe(2);
    expect(snapshot.aggregate.fails_count).toBeGreaterThanOrEqual(1);
  });

  it("(c) detects a regression when precision drops vs the prior snapshot", () => {
    // First run: A1 at 1.0 precision.
    const firstRun = buildDashboard({
      runner: new StubRunner(new Map()),
      fixtures: DEMO_FIXTURES,
      priorSnapshot: null,
    });
    expect(firstRun.snapshot.aggregate.regressions_count).toBe(0);

    // Second run: A1 drops to 0.80 (still may pass target, but regresses by 20pp).
    const overrides = new Map<string, RuleAccuracy>([
      [
        "A1",
        {
          rule_id: "A1",
          rule_name: "Prompt Injection",
          total: 5,
          passed: 4,
          failed: 1,
          true_positive_recall: 1.0,
          true_negative_precision: 0.80,
          edge_case_pass_rate: 1.0,
          failed_fixtures: [
            {
              rule_id: "A1",
              fixture_description: "false alarm",
              kind: "true_negative",
              expect_finding: false,
              got_finding: true,
              passed: false,
              elapsed_ms: 1,
            },
          ],
        },
      ],
    ]);

    const secondRun = buildDashboard({
      runner: new StubRunner(overrides),
      fixtures: DEMO_FIXTURES,
      priorSnapshot: firstRun.snapshot,
      regressionThreshold: 0.05,
    });

    const a1 = secondRun.snapshot.rules.find(r => r.rule_id === "A1")!;
    expect(a1.baseline_delta).toBe(false);
    expect(a1.delta_precision).toBeLessThan(-0.05);
    expect(a1.regressed).toBe(true);
    expect(secondRun.snapshot.aggregate.regressions_count).toBeGreaterThanOrEqual(1);

    // The trend markdown must mention the regression.
    const md = renderTrendMarkdown(secondRun.snapshot, firstRun.snapshot);
    expect(md).toMatch(/Regressions Since Last Run/);
    expect(md).toMatch(/A1/);
  });

  it("(d) emits latest.json that round-trips and is a valid DashboardSnapshot", () => {
    const { snapshot } = buildDashboard({
      runner: new StubRunner(new Map()),
      fixtures: DEMO_FIXTURES,
      priorSnapshot: null,
    });
    const json = renderLatestJson(snapshot);
    const parsed: DashboardSnapshot = JSON.parse(json);

    expect(parsed.rules.length).toBe(snapshot.rules.length);
    expect(parsed.aggregate.rule_count).toBe(snapshot.aggregate.rule_count);
    expect(parsed.rules[0].rule_id).toBe(snapshot.rules[0].rule_id);
    expect(parsed.retiredRules).toContain("O1");
    expect(parsed.retiredRules).toContain("M3");

    // Write → read round-trips
    const dir = mkdtempSync(join(tmpdir(), "mcp-sentinel-dash-"));
    try {
      const latestPath = join(dir, "latest.json");
      const trendPath = join(dir, "trend.md");
      writeDashboardArtefacts({ latestPath, trendPath, snapshot, priorSnapshot: null });
      const prior = readPriorSnapshot(latestPath);
      expect(prior).not.toBeNull();
      expect(prior!.rules.length).toBe(snapshot.rules.length);

      const trend = readFileSync(trendPath, "utf-8");
      expect(trend).toContain("# MCP Sentinel — Rule Accuracy Dashboard");
      expect(trend).toContain("| Rule |");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
