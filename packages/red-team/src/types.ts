import type { AnalysisContext } from "@mcp-sentinel/analyzer";

// ── Fixture types ──────────────────────────────────────────────────────────────

/** A single test case for one rule */
export interface RuleFixture {
  /** Short description of what this fixture is testing */
  description: string;
  /** The analysis context to run through the engine */
  context: Partial<AnalysisContext> & { server: AnalysisContext["server"] };
  /**
   * Expected outcome:
   *   true  → rule SHOULD fire (true positive)
   *   false → rule MUST NOT fire (true negative)
   */
  expect_finding: boolean;
  /**
   * Optional: if expect_finding=true, assert that evidence contains this substring.
   * Helps verify the finding is for the right reason, not an accidental match.
   */
  evidence_contains?: string;
  /** Fixture classification */
  kind: "true_positive" | "true_negative" | "edge_case";
  /** OWASP or MITRE reference for documentation */
  threat_ref?: string;
}

/** All fixtures for one rule */
export interface RuleFixtureSet {
  rule_id: string;
  rule_name: string;
  fixtures: RuleFixture[];
}

// ── Accuracy result types ──────────────────────────────────────────────────────

export interface FixtureResult {
  rule_id: string;
  fixture_description: string;
  kind: RuleFixture["kind"];
  expect_finding: boolean;
  got_finding: boolean;
  passed: boolean;
  evidence?: string;
  elapsed_ms: number;
}

export interface RuleAccuracy {
  rule_id: string;
  rule_name: string;
  total: number;
  passed: number;
  failed: number;
  true_positive_recall: number;   // TP / (TP + FN) — did it catch all it should?
  true_negative_precision: number; // TN / (TN + FP) — did it avoid false alarms?
  edge_case_pass_rate: number;
  failed_fixtures: FixtureResult[];
}

export interface AccuracyReport {
  generated_at: string;
  rules_version: string;
  total_rules_tested: number;
  total_fixtures: number;
  total_passed: number;
  total_failed: number;
  overall_precision: number;   // avg true_negative_precision across all rules
  overall_recall: number;      // avg true_positive_recall across all rules
  passes_layer5_threshold: boolean; // overall_precision >= 0.80
  by_category: Record<string, CategoryAccuracy>;
  by_rule: RuleAccuracy[];
  worst_performers: RuleAccuracy[]; // bottom 10 by combined score
}

export interface CategoryAccuracy {
  category: string;
  rules_count: number;
  avg_precision: number;
  avg_recall: number;
  passes_threshold: boolean;
}
