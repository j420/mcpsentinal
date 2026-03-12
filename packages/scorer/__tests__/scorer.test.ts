import { describe, it, expect } from "vitest";
import { computeScore } from "../src/scorer.js";
import type { FindingInput } from "@mcp-sentinel/database";

const ruleCategories: Record<string, string> = {
  A1: "description-analysis",
  B1: "schema-analysis",
  C1: "code-analysis",
  D1: "dependency-analysis",
  E1: "behavioral-analysis",
  F1: "ecosystem-context",
};

describe("computeScore", () => {
  it("returns 100 for no findings", () => {
    const result = computeScore([], ruleCategories);
    expect(result.total_score).toBe(100);
  });

  it("deducts 25 for a critical finding", () => {
    const findings: FindingInput[] = [
      {
        rule_id: "C1",
        severity: "critical",
        evidence: "exec() found",
        remediation: "Use execFile()",
        owasp_category: "MCP03-command-injection",
        mitre_technique: null,
      },
    ];

    const result = computeScore(findings, ruleCategories);
    expect(result.total_score).toBe(75);
  });

  it("deducts correctly for mixed severities", () => {
    const findings: FindingInput[] = [
      { rule_id: "C1", severity: "critical", evidence: "e", remediation: "r", owasp_category: null, mitre_technique: null },
      { rule_id: "B1", severity: "medium", evidence: "e", remediation: "r", owasp_category: null, mitre_technique: null },
      { rule_id: "E1", severity: "low", evidence: "e", remediation: "r", owasp_category: null, mitre_technique: null },
    ];

    // 100 - 25 - 8 - 3 = 64
    const result = computeScore(findings, ruleCategories);
    expect(result.total_score).toBe(64);
  });

  it("never goes below 0", () => {
    const findings: FindingInput[] = Array.from({ length: 10 }, (_, i) => ({
      rule_id: `C${i}`,
      severity: "critical" as const,
      evidence: "e",
      remediation: "r",
      owasp_category: null,
      mitre_technique: null,
    }));

    const result = computeScore(findings, ruleCategories);
    expect(result.total_score).toBe(0);
  });

  it("caps at 40 for lethal trifecta", () => {
    const findings: FindingInput[] = [
      {
        rule_id: "F1",
        severity: "critical",
        evidence: "lethal trifecta",
        remediation: "separate",
        owasp_category: "MCP04-data-exfiltration",
        mitre_technique: null,
      },
    ];

    // Would be 75 (100-25) but capped at 40
    const result = computeScore(findings, ruleCategories);
    expect(result.total_score).toBe(40);
  });

  it("tracks OWASP coverage correctly", () => {
    const findings: FindingInput[] = [
      { rule_id: "C1", severity: "high", evidence: "e", remediation: "r", owasp_category: "MCP03-command-injection", mitre_technique: null },
    ];

    const result = computeScore(findings, ruleCategories);
    expect(result.owasp_coverage["MCP03-command-injection"]).toBe(false); // has finding = not clean
    expect(result.owasp_coverage["MCP01-prompt-injection"]).toBe(true); // no finding = clean
  });

  it("computes category sub-scores independently", () => {
    const findings: FindingInput[] = [
      { rule_id: "C1", severity: "critical", evidence: "e", remediation: "r", owasp_category: null, mitre_technique: null },
      { rule_id: "A1", severity: "medium", evidence: "e", remediation: "r", owasp_category: null, mitre_technique: null },
    ];

    const result = computeScore(findings, ruleCategories);
    expect(result.code_score).toBe(75); // 100 - 25
    expect(result.description_score).toBe(92); // 100 - 8
    expect(result.deps_score).toBe(100); // untouched
    expect(result.behavior_score).toBe(100); // untouched
  });
});
