import { AnalysisEngine, type AnalysisContext } from "@mcp-sentinel/analyzer";
import { loadRules, getRulesVersion } from "@mcp-sentinel/analyzer";
import { fileURLToPath } from "url";
import { dirname, resolve } from "path";
import type {
  RuleFixture,
  RuleFixtureSet,
  FixtureResult,
  RuleAccuracy,
  AccuracyReport,
  CategoryAccuracy,
} from "./types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_RULES_DIR = resolve(__dirname, "../../../rules");

// ── Accuracy Runner ───────────────────────────────────────────────────────────

export class AccuracyRunner {
  private engine: AnalysisEngine;
  private rulesVersion: string;

  constructor(rulesDir = DEFAULT_RULES_DIR) {
    const rules = loadRules(rulesDir);
    this.engine = new AnalysisEngine(rules);
    this.rulesVersion = getRulesVersion(rules);
  }

  /**
   * Run a single fixture through the engine and return whether it passed.
   */
  runFixture(fixture: RuleFixture, ruleId: string): FixtureResult {
    const start = Date.now();

    // Build a complete AnalysisContext from the partial fixture context
    const ctx: AnalysisContext = {
      server: fixture.context.server,
      tools: fixture.context.tools ?? [],
      source_code: fixture.context.source_code ?? null,
      dependencies: fixture.context.dependencies ?? [],
      connection_metadata: fixture.context.connection_metadata ?? null,
      initialize_metadata: fixture.context.initialize_metadata,
      resources: fixture.context.resources,
      prompts: fixture.context.prompts,
      roots: fixture.context.roots,
      declared_capabilities: fixture.context.declared_capabilities,
    };

    const findings = this.engine.analyze(ctx);
    const matchingFindings = findings.filter((f) => f.rule_id === ruleId);

    const got_finding = matchingFindings.length > 0;
    const passed = got_finding === fixture.expect_finding;

    // If we expected a finding and got one, validate evidence_contains if set
    let evidencePassed = true;
    if (fixture.expect_finding && got_finding && fixture.evidence_contains) {
      evidencePassed = matchingFindings.some((f) =>
        f.evidence.includes(fixture.evidence_contains!)
      );
    }

    return {
      rule_id: ruleId,
      fixture_description: fixture.description,
      kind: fixture.kind,
      expect_finding: fixture.expect_finding,
      got_finding,
      passed: passed && evidencePassed,
      evidence: matchingFindings[0]?.evidence,
      elapsed_ms: Date.now() - start,
    };
  }

  /**
   * Run all fixtures for one rule and compute accuracy metrics.
   */
  runRuleFixtureSet(fixtureSet: RuleFixtureSet): RuleAccuracy {
    const results = fixtureSet.fixtures.map((f) => this.runFixture(f, fixtureSet.rule_id));

    const truePositives = results.filter(
      (r) => r.kind === "true_positive" && r.expect_finding === true
    );
    const trueNegatives = results.filter(
      (r) => r.kind === "true_negative" && r.expect_finding === false
    );
    const edgeCases = results.filter((r) => r.kind === "edge_case");

    const tpPassed = truePositives.filter((r) => r.passed).length;
    const tnPassed = trueNegatives.filter((r) => r.passed).length;
    const ecPassed = edgeCases.filter((r) => r.passed).length;

    // Recall: of all known-vulnerable fixtures, how many did we catch?
    const recall =
      truePositives.length > 0 ? tpPassed / truePositives.length : 1.0;

    // Precision (represented as TN pass rate): how rarely do we false-alarm?
    const precision =
      trueNegatives.length > 0 ? tnPassed / trueNegatives.length : 1.0;

    const ecRate =
      edgeCases.length > 0 ? ecPassed / edgeCases.length : 1.0;

    const totalPassed = results.filter((r) => r.passed).length;

    return {
      rule_id: fixtureSet.rule_id,
      rule_name: fixtureSet.rule_name,
      total: results.length,
      passed: totalPassed,
      failed: results.length - totalPassed,
      true_positive_recall: recall,
      true_negative_precision: precision,
      edge_case_pass_rate: ecRate,
      failed_fixtures: results.filter((r) => !r.passed),
    };
  }

  /**
   * Run all fixture sets and produce the full accuracy report.
   */
  runAll(fixtureSets: RuleFixtureSet[]): AccuracyReport {
    const byRule = fixtureSets.map((fs) => this.runRuleFixtureSet(fs));

    const totalFixtures = byRule.reduce((s, r) => s + r.total, 0);
    const totalPassed = byRule.reduce((s, r) => s + r.passed, 0);
    const totalFailed = byRule.reduce((s, r) => s + r.failed, 0);

    const overallPrecision =
      byRule.length > 0
        ? byRule.reduce((s, r) => s + r.true_negative_precision, 0) / byRule.length
        : 1.0;

    const overallRecall =
      byRule.length > 0
        ? byRule.reduce((s, r) => s + r.true_positive_recall, 0) / byRule.length
        : 1.0;

    // Category breakdown
    const categoryMap: Record<string, RuleAccuracy[]> = {};
    for (const r of byRule) {
      const cat = r.rule_id[0].toUpperCase(); // e.g. "A" from "A1"
      if (!categoryMap[cat]) categoryMap[cat] = [];
      categoryMap[cat].push(r);
    }

    const byCategory: Record<string, CategoryAccuracy> = {};
    for (const [cat, rules] of Object.entries(categoryMap)) {
      const avgPrec =
        rules.reduce((s, r) => s + r.true_negative_precision, 0) / rules.length;
      const avgRecall =
        rules.reduce((s, r) => s + r.true_positive_recall, 0) / rules.length;
      byCategory[cat] = {
        category: cat,
        rules_count: rules.length,
        avg_precision: avgPrec,
        avg_recall: avgRecall,
        passes_threshold: avgPrec >= 0.8 && avgRecall >= 0.8,
      };
    }

    // Worst 10 performers by combined score (precision * recall)
    const sorted = [...byRule].sort(
      (a, b) =>
        a.true_positive_recall * a.true_negative_precision -
        b.true_positive_recall * b.true_negative_precision
    );
    const worstPerformers = sorted.slice(0, 10);

    return {
      generated_at: new Date().toISOString(),
      rules_version: this.rulesVersion,
      total_rules_tested: byRule.length,
      total_fixtures: totalFixtures,
      total_passed: totalPassed,
      total_failed: totalFailed,
      overall_precision: overallPrecision,
      overall_recall: overallRecall,
      passes_layer5_threshold: overallPrecision >= 0.8,
      by_category: byCategory,
      by_rule: byRule,
      worst_performers: worstPerformers,
    };
  }
}
