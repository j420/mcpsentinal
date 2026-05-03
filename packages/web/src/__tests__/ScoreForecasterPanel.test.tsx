// @vitest-environment jsdom
/**
 * Score Forecaster — interactive behaviour tests.
 *
 * The panel's value rests on the projection being faithful to the
 * scorer's `100 − Σ(penalty)` formula, with the lethal-trifecta cap at
 * 40. These tests pin both: the math AND the toggle behaviour.
 */

import { describe, it, expect } from "vitest";
import React from "react";
import { render, fireEvent } from "@testing-library/react";
import ScoreForecasterPanel from "../components/audit/ScoreForecasterPanel";
import type { DeepDiveCategory, DeepDiveFinding } from "@/lib/deep-dive";

function f(over: Partial<DeepDiveFinding> & { id: string; severity: DeepDiveFinding["severity"] }): DeepDiveFinding {
  return {
    confidence: 1.0,
    evidence: "sample",
    evidence_chain: null,
    remediation: "sample remediation",
    ...over,
  } as DeepDiveFinding;
}

function rule(rule_id: string, name: string, findings: DeepDiveFinding[]) {
  return {
    rule_id,
    name,
    severity: findings[0]?.severity ?? "low",
    category: "C",
    owasp: null,
    mitre: null,
    summary: "",
    framework_controls: [],
    methodology: { technique: "n/a", verified_edge_cases: [], edge_case_strategies: [], confidence_cap: null },
    backing: null,
    remediation: "rule-level remediation",
    status: "findings" as const,
    findings,
  };
}

function cat(rules: ReturnType<typeof rule>[]): DeepDiveCategory {
  return {
    id: "cat-1",
    title: "Test category",
    summary: "",
    frameworks: [],
    counts: {
      rules_total: rules.length,
      rules_passed: 0,
      rules_with_findings: rules.length,
      rules_skipped: 0,
      finding_count: rules.reduce((s, r) => s + r.findings.length, 0),
      severity_breakdown: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
    },
    sub_categories: [
      {
        id: "sub-1", title: "Sub", summary: "",
        counts: {
          rules_total: rules.length, rules_passed: 0, rules_with_findings: rules.length,
          rules_skipped: 0, finding_count: rules.reduce((s, r) => s + r.findings.length, 0),
          severity_breakdown: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
        },
        rules,
      },
    ],
  };
}

describe("ScoreForecasterPanel — empty state", () => {
  it("renders an honest empty panel when no findings exist", () => {
    const { getByLabelText, container } = render(
      <ScoreForecasterPanel currentScore={100} categories={[]} />,
    );
    expect(getByLabelText(/no findings to model/i)).toBeTruthy();
    expect(container.querySelectorAll(".audit-forecast-finding")).toHaveLength(0);
  });
});

describe("ScoreForecasterPanel — score projection math", () => {
  it("projects score = current + recoveries when findings are toggled", () => {
    // 1 critical (weight 25 × confidence 1.0 = 25)
    const categories = [cat([rule("X1", "Critical issue", [f({ id: "f1", severity: "critical", confidence: 1.0 })])])];
    const { container } = render(
      <ScoreForecasterPanel currentScore={50} categories={categories} />,
    );
    // Initial projected = 50
    const beforeProjected = container.querySelectorAll(".audit-forecast-meter-num")[1];
    expect(beforeProjected?.textContent).toBe("50");

    // Toggle the finding as resolved
    const cb = container.querySelector(".audit-forecast-finding-cb") as HTMLInputElement;
    fireEvent.click(cb);

    const afterProjected = container.querySelectorAll(".audit-forecast-meter-num")[1];
    // 50 + 25 = 75
    expect(afterProjected?.textContent).toBe("75");
  });

  it("scales penalty by confidence (60% confidence high → 9 pts, not 15)", () => {
    const categories = [cat([rule("X2", "High issue", [f({ id: "f2", severity: "high", confidence: 0.6 })])])];
    const { container } = render(
      <ScoreForecasterPanel currentScore={70} categories={categories} />,
    );
    const cb = container.querySelector(".audit-forecast-finding-cb") as HTMLInputElement;
    fireEvent.click(cb);
    const projected = container.querySelectorAll(".audit-forecast-meter-num")[1];
    // 15 × 0.6 = 9, so 70 + 9 = 79
    expect(projected?.textContent).toBe("79");
  });

  it("caps projected score at 100 even with massive recovery", () => {
    const categories = [
      cat([
        rule("X3", "Critical 1", [f({ id: "f3", severity: "critical", confidence: 1.0 })]),
        rule("X4", "Critical 2", [f({ id: "f4", severity: "critical", confidence: 1.0 })]),
        rule("X5", "Critical 3", [f({ id: "f5", severity: "critical", confidence: 1.0 })]),
        rule("X6", "Critical 4", [f({ id: "f6", severity: "critical", confidence: 1.0 })]),
      ]),
    ];
    const { container } = render(
      <ScoreForecasterPanel currentScore={50} categories={categories} />,
    );
    // Toggle every finding
    container.querySelectorAll(".audit-forecast-finding-cb").forEach((cb) => {
      fireEvent.click(cb as HTMLInputElement);
    });
    const projected = container.querySelectorAll(".audit-forecast-meter-num")[1];
    // 50 + 100 = 150 → capped at 100
    expect(projected?.textContent).toBe("100");
  });

  it("applies the lethal-trifecta cap at 40 when F1 remains unresolved", () => {
    const categories = [
      cat([
        rule("F1", "Lethal trifecta", [f({ id: "fT", severity: "critical", confidence: 1.0 })]),
        rule("X8", "Other critical", [f({ id: "f8", severity: "critical", confidence: 1.0 })]),
      ]),
    ];
    const { container } = render(
      <ScoreForecasterPanel currentScore={20} categories={categories} />,
    );
    // Resolve only the non-trifecta finding
    const cbs = container.querySelectorAll(".audit-forecast-finding-cb");
    // The trifecta finding sorts first by recovery (same recovery, but
    // F1 has the trifecta flag — order is by recovery desc, ties broken
    // by insertion order; it's deterministic but we don't care which
    // checkbox we click here as long as we leave the trifecta unresolved.
    // We resolve the second one instead.
    fireEvent.click(cbs[1] as HTMLInputElement);
    const projected = container.querySelectorAll(".audit-forecast-meter-num")[1];
    // 20 + 25 = 45, capped at 40 because the trifecta is still tripped
    expect(projected?.textContent).toBe("40");
  });

  it("releases the trifecta cap when the trifecta finding is resolved", () => {
    const categories = [
      cat([
        rule("F1", "Lethal trifecta", [f({ id: "fT", severity: "critical", confidence: 1.0 })]),
        rule("X9", "Other critical", [f({ id: "f9", severity: "critical", confidence: 1.0 })]),
      ]),
    ];
    const { container } = render(
      <ScoreForecasterPanel currentScore={20} categories={categories} />,
    );
    // Resolve every finding including the trifecta — cap should lift.
    container.querySelectorAll(".audit-forecast-finding-cb").forEach((cb) => {
      fireEvent.click(cb as HTMLInputElement);
    });
    const projected = container.querySelectorAll(".audit-forecast-meter-num")[1];
    // 20 + 50 = 70, no cap applied because trifecta is resolved
    expect(projected?.textContent).toBe("70");
  });
});

describe("ScoreForecasterPanel — toggle behaviour", () => {
  it("shows the remediation only when a finding is toggled on", () => {
    const categories = [cat([rule("X1", "Issue", [f({ id: "f1", severity: "high", remediation: "Run pnpm fix" })])])];
    const { container } = render(
      <ScoreForecasterPanel currentScore={70} categories={categories} />,
    );
    expect(container.querySelector(".audit-forecast-remediation")).toBeNull();
    fireEvent.click(container.querySelector(".audit-forecast-finding-cb") as HTMLInputElement);
    expect(container.querySelector(".audit-forecast-remediation")?.textContent).toBe("Run pnpm fix");
  });

  it("Reset button clears all toggles and restores current score", () => {
    const categories = [cat([rule("X1", "Issue", [f({ id: "f1", severity: "critical" })])])];
    const { container } = render(
      <ScoreForecasterPanel currentScore={50} categories={categories} />,
    );
    // No reset button before any toggle
    expect(container.querySelector(".audit-forecast-reset")).toBeNull();
    fireEvent.click(container.querySelector(".audit-forecast-finding-cb") as HTMLInputElement);
    const reset = container.querySelector(".audit-forecast-reset") as HTMLButtonElement | null;
    expect(reset).toBeTruthy();
    fireEvent.click(reset as HTMLButtonElement);
    const projected = container.querySelectorAll(".audit-forecast-meter-num")[1];
    expect(projected?.textContent).toBe("50");
  });

  it("excludes non-canonical (cross-referenced) rule placements from the projection", () => {
    // Same finding rendered in two sub-categories — only the canonical
    // placement counts. Otherwise the same finding's penalty would be
    // applied twice.
    const sharedFinding = f({ id: "shared", severity: "critical", confidence: 1.0 });
    const canonical = rule("X1", "Issue", [sharedFinding]);
    const crossRef = { ...rule("X1", "Issue", [sharedFinding]), is_canonical: false };
    const categories: DeepDiveCategory[] = [
      cat([canonical]),
      { ...cat([crossRef]), id: "cat-2", title: "Cat 2" },
    ];
    const { container } = render(
      <ScoreForecasterPanel currentScore={50} categories={categories} />,
    );
    // The seen-set in the forecaster also dedupes by finding.id so even
    // if is_canonical drift slipped in, the projection would still only
    // count the finding once. This test pins both invariants together.
    const rows = container.querySelectorAll(".audit-forecast-finding");
    expect(rows.length).toBe(1);
  });
});
