/**
 * Scorer — Confidence Weighting Tests
 *
 * Philosophy: "Live Evidence, Not Static Claims"
 * A finding backed by AST taint analysis (0.95 confidence) should penalize
 * more than a regex-only pattern match (0.50 confidence). The scorer must
 * scale penalties proportionally so that low-evidence findings don't dominate
 * a server's score.
 *
 * These tests verify:
 * 1. Confidence weighting scales penalties correctly
 * 2. Backward compatibility: findings without confidence default to full penalty
 * 3. Sub-scores are affected by confidence weighting
 * 4. Edge cases: zero confidence, max confidence, mixed
 * 5. Lethal trifecta still caps at 40 regardless of confidence
 * 6. Penalty breakdown reflects actual weighted penalties
 */
import { describe, it, expect } from "vitest";
import { computeScore } from "../src/scorer.js";

const ruleCategories: Record<string, string> = {
  A1: "description-analysis",
  B1: "schema-analysis",
  C1: "code-analysis",
  D1: "dependency-analysis",
  E1: "behavioral-analysis",
  F1: "ecosystem-context",
  I13: "protocol-surface",
};

// Helper: finding with confidence
function finding(
  rule_id: string,
  severity: string,
  confidence?: number,
) {
  return {
    rule_id,
    severity,
    evidence: `test evidence for ${rule_id}`,
    remediation: "fix it",
    owasp_category: null as string | null,
    mitre_technique: null as string | null,
    ...(confidence !== undefined ? { confidence } : {}),
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 1: Core Confidence Weighting
// ═══════════════════════════════════════════════════════════════════════════════

describe("Confidence Weighting — Core Behavior", () => {
  it("full confidence (1.0) applies full penalty", () => {
    // Critical = 25 points. Confidence 1.0 → penalty = 25
    const result = computeScore([finding("C1", "critical", 1.0)], ruleCategories);
    expect(result.total_score).toBe(75); // 100 - 25
  });

  it("half confidence (0.50) applies half penalty", () => {
    // Critical = 25 points. Confidence 0.50 → penalty = 12.5
    const result = computeScore([finding("C1", "critical", 0.50)], ruleCategories);
    expect(result.total_score).toBe(87.5); // 100 - 12.5
  });

  it("low confidence (0.20) applies proportionally small penalty", () => {
    // Critical = 25 points. Confidence 0.20 → penalty = 5
    const result = computeScore([finding("C1", "critical", 0.20)], ruleCategories);
    expect(result.total_score).toBe(95); // 100 - 5
  });

  it("high confidence finding penalizes more than low confidence finding", () => {
    const highConf = computeScore([finding("C1", "critical", 0.95)], ruleCategories);
    const lowConf = computeScore([finding("C1", "critical", 0.50)], ruleCategories);
    expect(highConf.total_score).toBeLessThan(lowConf.total_score);
  });

  it("two low-confidence findings penalize less than one high-confidence finding", () => {
    // Two findings at 0.30 confidence: 2 * (25 * 0.30) = 15 penalty → score 85
    const twoLow = computeScore(
      [finding("C1", "critical", 0.30), finding("C1", "critical", 0.30)],
      ruleCategories,
    );
    // One finding at 0.95 confidence: 25 * 0.95 = 23.75 penalty → score 76.25
    const oneHigh = computeScore([finding("C1", "critical", 0.95)], ruleCategories);
    expect(twoLow.total_score).toBeGreaterThan(oneHigh.total_score);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 2: Backward Compatibility
// ═══════════════════════════════════════════════════════════════════════════════

describe("Backward Compatibility", () => {
  it("findings WITHOUT confidence default to full penalty (1.0)", () => {
    // No confidence field → should behave exactly like pre-upgrade
    const result = computeScore([finding("C1", "critical")], ruleCategories);
    expect(result.total_score).toBe(75); // 100 - 25 (full penalty)
  });

  it("mixed findings: some with confidence, some without", () => {
    const result = computeScore(
      [
        finding("C1", "critical"),        // No confidence → 25 penalty
        finding("A1", "medium", 0.50),    // 0.50 confidence → 4 penalty (8 * 0.5)
      ],
      ruleCategories,
    );
    expect(result.total_score).toBe(71); // 100 - 25 - 4
  });

  it("score 100 for no findings (unchanged)", () => {
    const result = computeScore([], ruleCategories);
    expect(result.total_score).toBe(100);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 3: Sub-Score Weighting
// ═══════════════════════════════════════════════════════════════════════════════

describe("Sub-Score Confidence Weighting", () => {
  it("code_score is reduced proportionally by confidence", () => {
    // C1 maps to code_score. Critical = 25. Confidence 0.50 → penalty 12.5
    const result = computeScore([finding("C1", "critical", 0.50)], ruleCategories);
    expect(result.code_score).toBe(87.5); // 100 - 12.5
  });

  it("description_score is reduced proportionally by confidence", () => {
    // A1 maps to description_score. Medium = 8. Confidence 0.75 → penalty 6
    const result = computeScore([finding("A1", "medium", 0.75)], ruleCategories);
    expect(result.description_score).toBe(94); // 100 - 6
  });

  it("unaffected sub-scores remain 100", () => {
    const result = computeScore([finding("C1", "critical", 0.50)], ruleCategories);
    expect(result.deps_score).toBe(100);
    expect(result.config_score).toBe(100);
    expect(result.description_score).toBe(100);
    expect(result.behavior_score).toBe(100);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 4: Penalty Breakdown Transparency
// ═══════════════════════════════════════════════════════════════════════════════

describe("Penalty Breakdown", () => {
  it("breakdown shows actual weighted penalty (not base penalty)", () => {
    const result = computeScore([finding("C1", "critical", 0.50)], ruleCategories);
    expect(result.penalty_breakdown).toHaveLength(1);
    expect(result.penalty_breakdown[0].penalty).toBe(12.5); // 25 * 0.50
    expect(result.penalty_breakdown[0].rule_id).toBe("C1");
    expect(result.penalty_breakdown[0].severity).toBe("critical");
  });

  it("breakdown shows full penalty when no confidence provided", () => {
    const result = computeScore([finding("C1", "critical")], ruleCategories);
    expect(result.penalty_breakdown[0].penalty).toBe(25);
  });

  it("total of breakdown penalties matches total score deduction", () => {
    const result = computeScore(
      [
        finding("C1", "critical", 0.80),   // 25 * 0.80 = 20
        finding("A1", "medium", 0.60),     // 8 * 0.60 = 4.8
        finding("E1", "low", 0.90),        // 3 * 0.90 = 2.7
      ],
      ruleCategories,
    );
    const totalPenalty = result.penalty_breakdown.reduce((sum, p) => sum + p.penalty, 0);
    expect(result.total_score).toBe(Math.max(0, 100 - totalPenalty));
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 5: Edge Cases
// ═══════════════════════════════════════════════════════════════════════════════

describe("Edge Cases", () => {
  it("zero confidence means zero penalty", () => {
    const result = computeScore([finding("C1", "critical", 0)], ruleCategories);
    expect(result.total_score).toBe(100); // 25 * 0 = 0 penalty
  });

  it("confidence > 1.0 still works (scales beyond base)", () => {
    // This shouldn't normally happen but the scorer should handle it gracefully
    const result = computeScore([finding("C1", "critical", 1.5)], ruleCategories);
    // 25 * 1.5 = 37.5
    expect(result.total_score).toBe(62.5);
  });

  it("score never goes below 0 even with high-confidence findings", () => {
    const findings = Array.from({ length: 10 }, (_, i) =>
      finding(`C${i}`, "critical", 1.0),
    );
    const result = computeScore(findings, ruleCategories);
    expect(result.total_score).toBe(0);
  });

  it("all severities weighted correctly at 0.50 confidence", () => {
    const half = 0.50;
    const results = {
      critical: computeScore([finding("C1", "critical", half)], ruleCategories).total_score,
      high: computeScore([finding("C1", "high", half)], ruleCategories).total_score,
      medium: computeScore([finding("C1", "medium", half)], ruleCategories).total_score,
      low: computeScore([finding("C1", "low", half)], ruleCategories).total_score,
      informational: computeScore([finding("C1", "informational", half)], ruleCategories).total_score,
    };
    expect(results.critical).toBe(87.5);    // 100 - 25*0.5
    expect(results.high).toBe(92.5);        // 100 - 15*0.5
    expect(results.medium).toBe(96);        // 100 - 8*0.5
    expect(results.low).toBe(98.5);         // 100 - 3*0.5
    expect(results.informational).toBe(99.5); // 100 - 1*0.5
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 6: Lethal Trifecta + Confidence
// ═══════════════════════════════════════════════════════════════════════════════

describe("Lethal Trifecta with Confidence", () => {
  it("F1 caps at 40 regardless of confidence", () => {
    // Even with low confidence, lethal trifecta means the score is capped
    const result = computeScore(
      [{ ...finding("F1", "critical", 0.50), owasp_category: "MCP04-data-exfiltration" }],
      ruleCategories,
    );
    expect(result.total_score).toBe(40);
  });

  it("I13 caps at 40 regardless of confidence", () => {
    const result = computeScore(
      [{ ...finding("I13", "critical", 0.50), owasp_category: "MCP04-data-exfiltration" }],
      ruleCategories,
    );
    expect(result.total_score).toBe(40);
  });

  it("lethal trifecta cap applies even when weighted score would be above 40", () => {
    // F1 critical at 0.10 confidence: penalty = 2.5, score = 97.5
    // But cap at 40
    const result = computeScore(
      [{ ...finding("F1", "critical", 0.10), owasp_category: "MCP04-data-exfiltration" }],
      ruleCategories,
    );
    expect(result.total_score).toBe(40);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 7: Real-World Scenarios
// ═══════════════════════════════════════════════════════════════════════════════

describe("Real-World Scoring Scenarios", () => {
  it("AST-confirmed C1 (0.95) vs regex-only C1 (0.50): different scores", () => {
    const astConfirmed = computeScore([finding("C1", "critical", 0.95)], ruleCategories);
    const regexOnly = computeScore([finding("C1", "critical", 0.50)], ruleCategories);

    // AST: 100 - 23.75 = 76.25
    // Regex: 100 - 12.5 = 87.5
    expect(astConfirmed.total_score).toBeLessThan(regexOnly.total_score);
    // The difference should be meaningful (> 5 points)
    expect(regexOnly.total_score - astConfirmed.total_score).toBeGreaterThan(5);
  });

  it("server with mixed confidence findings scores fairly", () => {
    const result = computeScore(
      [
        finding("C1", "critical", 0.95),    // AST-confirmed RCE: 25 * 0.95 = 23.75
        finding("A1", "high", 0.80),        // Strong injection signal: 15 * 0.80 = 12
        finding("B1", "medium", 0.60),      // Moderate schema issue: 8 * 0.60 = 4.8
        finding("E1", "low", 0.40),         // Weak behavioral: 3 * 0.40 = 1.2
      ],
      ruleCategories,
    );
    // Total penalty: 23.75 + 12 + 4.8 + 1.2 = 41.75
    // Score: 100 - 41.75 = 58.25
    const expectedPenalty = 23.75 + 12 + 4.8 + 1.2;
    expect(result.total_score).toBeCloseTo(100 - expectedPenalty, 1);
  });

  it("OWASP coverage tracks findings regardless of confidence", () => {
    const result = computeScore(
      [{ ...finding("C1", "critical", 0.10), owasp_category: "MCP03-command-injection" }],
      ruleCategories,
    );
    // Even at 0.10 confidence, the finding still marks the OWASP category
    expect(result.owasp_coverage["MCP03-command-injection"]).toBe(false);
    expect(result.owasp_coverage["MCP01-prompt-injection"]).toBe(true);
  });
});
