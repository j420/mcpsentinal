import { describe, it, expect } from "vitest";
import { computeScore, type AnalysisCoverageInput } from "../src/scorer.js";
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

  it("caps at 40 for cross-config lethal trifecta (I13)", () => {
    const findings: FindingInput[] = [
      {
        rule_id: "I13",
        severity: "critical",
        evidence: "cross-config lethal trifecta",
        remediation: "separate configs",
        owasp_category: "MCP04-data-exfiltration",
        mitre_technique: null,
      },
    ];

    const categoriesWithI13 = { ...ruleCategories, I13: "protocol-surface" };
    const result = computeScore(findings, categoriesWithI13);
    expect(result.total_score).toBe(40);
  });

  it("maps protocol-surface rules to config_score", () => {
    const findings: FindingInput[] = [
      {
        rule_id: "I1",
        severity: "high",
        evidence: "annotation deception",
        remediation: "fix",
        owasp_category: null,
        mitre_technique: null,
      },
    ];

    const categoriesWithI = { ...ruleCategories, I1: "protocol-surface" };
    const result = computeScore(findings, categoriesWithI);
    expect(result.config_score).toBe(85); // 100 - 15
    expect(result.code_score).toBe(100); // untouched
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

// ── v2 Sub-Score Tests ──────────────────────────────────────────────────────
// These validate that the 8 balanced sub-scores distribute penalties correctly
// instead of dumping everything into config_score.

describe("v2 sub-scores", () => {
  it("maps compliance-governance rules to compliance_score (not config_score)", () => {
    const findings: FindingInput[] = [
      { rule_id: "K1", severity: "high", evidence: "e", remediation: "r", owasp_category: null, mitre_technique: null },
    ];
    const categories = { K1: "compliance-governance" };
    const result = computeScore(findings, categories);

    // v2: compliance_score absorbs K1
    expect(result.compliance_score).toBe(85); // 100 - 15
    // v2: other sub-scores untouched
    expect(result.adversarial_score).toBe(100);
    expect(result.protocol_score).toBe(100);
    expect(result.infrastructure_score).toBe(100);
    // Legacy: config_score still absorbs it (backward compat)
    expect(result.config_score).toBe(85);
  });

  it("maps adversarial-ai rules to adversarial_score", () => {
    const findings: FindingInput[] = [
      { rule_id: "G1", severity: "critical", evidence: "e", remediation: "r", owasp_category: null, mitre_technique: null },
    ];
    const categories = { G1: "adversarial-ai" };
    const result = computeScore(findings, categories);

    expect(result.adversarial_score).toBe(75); // 100 - 25
    expect(result.compliance_score).toBe(100); // untouched
    // Legacy: still goes to config_score
    expect(result.config_score).toBe(75);
  });

  it("maps protocol-surface rules to protocol_score", () => {
    const findings: FindingInput[] = [
      { rule_id: "I1", severity: "high", evidence: "e", remediation: "r", owasp_category: null, mitre_technique: null },
    ];
    const categories = { I1: "protocol-surface" };
    const result = computeScore(findings, categories);

    expect(result.protocol_score).toBe(85);
    expect(result.adversarial_score).toBe(100);
    expect(result.compliance_score).toBe(100);
  });

  it("maps schema-analysis rules to schema_score (not config_score)", () => {
    const findings: FindingInput[] = [
      { rule_id: "B1", severity: "medium", evidence: "e", remediation: "r", owasp_category: null, mitre_technique: null },
    ];
    const categories = { B1: "schema-analysis" };
    const result = computeScore(findings, categories);

    // v2: schema_score absorbs B1
    expect(result.schema_score).toBe(92); // 100 - 8
    // Legacy: config_score still absorbs it
    expect(result.config_score).toBe(92);
  });

  it("maps supply-chain-advanced rules to supply_chain_score", () => {
    const findings: FindingInput[] = [
      { rule_id: "L1", severity: "high", evidence: "e", remediation: "r", owasp_category: null, mitre_technique: null },
      { rule_id: "D1", severity: "high", evidence: "e", remediation: "r", owasp_category: null, mitre_technique: null },
    ];
    const categories = { L1: "supply-chain-advanced", D1: "dependency-analysis" };
    const result = computeScore(findings, categories);

    // v2: both map to supply_chain_score
    expect(result.supply_chain_score).toBe(70); // 100 - 15 - 15
    // Legacy: L1 → config_score, D1 → deps_score (split)
    expect(result.config_score).toBe(85);
    expect(result.deps_score).toBe(85);
  });

  it("maps infrastructure/AI-runtime/privacy rules to infrastructure_score", () => {
    const findings: FindingInput[] = [
      { rule_id: "M1", severity: "medium", evidence: "e", remediation: "r", owasp_category: null, mitre_technique: null },
      { rule_id: "P1", severity: "medium", evidence: "e", remediation: "r", owasp_category: null, mitre_technique: null },
      { rule_id: "Q1", severity: "medium", evidence: "e", remediation: "r", owasp_category: null, mitre_technique: null },
    ];
    const categories = { M1: "ai-runtime-exploitation", P1: "infrastructure-runtime", Q1: "cross-ecosystem-emergent" };
    const result = computeScore(findings, categories);

    // v2: all three map to infrastructure_score
    expect(result.infrastructure_score).toBe(76); // 100 - 8 - 8 - 8
    // Legacy: all three still go to config_score
    expect(result.config_score).toBe(76);
  });

  it("returns 100 for all v2 sub-scores when no findings", () => {
    const result = computeScore([], {});
    expect(result.schema_score).toBe(100);
    expect(result.ecosystem_score).toBe(100);
    expect(result.protocol_score).toBe(100);
    expect(result.adversarial_score).toBe(100);
    expect(result.compliance_score).toBe(100);
    expect(result.supply_chain_score).toBe(100);
    expect(result.infrastructure_score).toBe(100);
  });
});

// ── Coverage-Aware Scoring Tests ────────────────────────────────────────────
// Validates that scores include coverage metadata for transparent reporting.

describe("coverage-aware scoring", () => {
  it("includes analysis_coverage when coverage is provided", () => {
    const coverage: AnalysisCoverageInput = {
      had_source_code: true,
      had_connection: true,
      had_dependencies: true,
      coverage_ratio: 0.85,
      confidence_band: "high",
      techniques_run: ["ast-taint", "capability-graph", "entropy"],
      rules_executed: 150,
      rules_skipped_no_data: 27,
    };

    const result = computeScore([], ruleCategories, coverage);
    expect(result.analysis_coverage).toBeDefined();
    expect(result.analysis_coverage!.confidence_band).toBe("high");
    expect(result.analysis_coverage!.had_source_code).toBe(true);
    expect(result.analysis_coverage!.techniques_run).toContain("ast-taint");
    expect(result.analysis_coverage!.rules_executed).toBe(150);
  });

  it("omits analysis_coverage when coverage is not provided", () => {
    const result = computeScore([], ruleCategories);
    expect(result.analysis_coverage).toBeUndefined();
  });

  it("includes low-confidence coverage for metadata-only scans", () => {
    const coverage: AnalysisCoverageInput = {
      had_source_code: false,
      had_connection: false,
      had_dependencies: false,
      coverage_ratio: 0.25,
      confidence_band: "minimal",
      techniques_run: ["linguistic"],
      rules_executed: 44,
      rules_skipped_no_data: 133,
    };

    const findings: FindingInput[] = [
      { rule_id: "A1", severity: "medium", evidence: "e", remediation: "r", owasp_category: null, mitre_technique: null },
    ];

    const result = computeScore(findings, ruleCategories, coverage);
    expect(result.total_score).toBe(92);
    expect(result.analysis_coverage!.confidence_band).toBe("minimal");
    expect(result.analysis_coverage!.rules_skipped_no_data).toBe(133);
    // This score of 92 should be displayed as "92/100 (minimal confidence)"
    // — telling the org that most rules couldn't run due to missing data
  });
});
