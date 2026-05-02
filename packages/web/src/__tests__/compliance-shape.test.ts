import { describe, expect, it } from "vitest";
import {
  buildComplianceShape,
  type ComplianceFramework,
} from "@/lib/compliance-shape";
import type { DeepDiveCategory, DeepDiveRule } from "@/lib/deep-dive";

function rule(overrides: Partial<DeepDiveRule> & {
  rule_id: string;
  framework_controls?: DeepDiveRule["framework_controls"];
}): DeepDiveRule {
  return {
    rule_id: overrides.rule_id,
    name: overrides.name ?? overrides.rule_id,
    severity: overrides.severity ?? "medium",
    category: overrides.category ?? "C",
    owasp: null,
    mitre: null,
    summary: "",
    framework_controls: overrides.framework_controls ?? [],
    methodology: {
      technique: "ast-taint",
      verified_edge_cases: [],
      edge_case_strategies: [],
      confidence_cap: null,
    },
    backing: null,
    remediation: "—",
    status: overrides.status ?? "passed",
    findings: overrides.findings ?? [],
  };
}

function emptySev() {
  return {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  };
}

function category(rules: DeepDiveRule[]): DeepDiveCategory {
  return {
    id: "x",
    title: "X",
    summary: "",
    frameworks: [],
    counts: {
      rules_total: rules.length,
      rules_passed: 0,
      rules_with_findings: 0,
      rules_skipped: 0,
      finding_count: 0,
      severity_breakdown: emptySev(),
    },
    sub_categories: [
      {
        id: "y",
        title: "Y",
        summary: "",
        counts: {
          rules_total: rules.length,
          rules_passed: 0,
          rules_with_findings: 0,
          rules_skipped: 0,
          finding_count: 0,
          severity_breakdown: emptySev(),
        },
        rules,
      },
    ],
  };
}

describe("buildComplianceShape", () => {
  it("returns [] when categories is undefined / empty", () => {
    expect(buildComplianceShape(undefined)).toEqual([]);
    expect(buildComplianceShape([])).toEqual([]);
  });

  it("returns [] when no rule carries framework_controls", () => {
    const cat = category([rule({ rule_id: "C1" })]);
    expect(buildComplianceShape([cat])).toEqual([]);
  });

  it("groups rules by framework_id then control_id", () => {
    const r1 = rule({
      rule_id: "K1",
      status: "passed",
      framework_controls: [
        { framework_id: "eu_ai_act", control_id: "Article 12", control_title: "Record-keeping" },
        { framework_id: "iso_27001", control_id: "A.8.15", control_title: "Logging" },
      ],
    });
    const r2 = rule({
      rule_id: "K2",
      status: "passed",
      framework_controls: [
        { framework_id: "eu_ai_act", control_id: "Article 12", control_title: "Record-keeping" },
      ],
    });
    const out = buildComplianceShape([category([r1, r2])]);
    expect(out.length).toBe(2);
    const eu = out.find((f) => f.framework_id === "eu_ai_act")!;
    expect(eu).toBeDefined();
    expect(eu.controls.length).toBe(1);
    expect(eu.controls[0]!.control_id).toBe("Article 12");
    expect(eu.controls[0]!.rules.map((r) => r.rule_id)).toEqual(["K1", "K2"]);
    const iso = out.find((f) => f.framework_id === "iso_27001")!;
    expect(iso.controls.length).toBe(1);
    expect(iso.controls[0]!.rules.map((r) => r.rule_id)).toEqual(["K1"]);
  });

  it("derives status MET when every rule passed", () => {
    const r = rule({
      rule_id: "K1",
      status: "passed",
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "Prompt Injection" },
      ],
    });
    const out = buildComplianceShape([category([r])]);
    expect(out[0]!.controls[0]!.status).toBe("met");
  });

  it("derives status UNMET when any rule has a finding at high severity", () => {
    const r = rule({
      rule_id: "K1",
      status: "findings",
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "Prompt Injection" },
      ],
      findings: [
        {
          id: "f1",
          severity: "high",
          confidence: 0.9,
          evidence: "x",
          evidence_chain: null,
          remediation: "y",
        },
      ],
    });
    const out = buildComplianceShape([category([r])]);
    expect(out[0]!.controls[0]!.status).toBe("unmet");
  });

  it("derives status UNMET when any rule has a critical finding", () => {
    const r = rule({
      rule_id: "K1",
      status: "findings",
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "Prompt Injection" },
      ],
      findings: [
        {
          id: "f1",
          severity: "critical",
          confidence: 0.9,
          evidence: "x",
          evidence_chain: null,
          remediation: "y",
        },
      ],
    });
    const out = buildComplianceShape([category([r])]);
    expect(out[0]!.controls[0]!.status).toBe("unmet");
  });

  it("derives status PARTIAL when there are findings but only at medium-or-below severity", () => {
    const r = rule({
      rule_id: "K1",
      status: "findings",
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "Prompt Injection" },
      ],
      findings: [
        {
          id: "f1",
          severity: "medium",
          confidence: 0.6,
          evidence: "x",
          evidence_chain: null,
          remediation: "y",
        },
      ],
    });
    const out = buildComplianceShape([category([r])]);
    expect(out[0]!.controls[0]!.status).toBe("partial");
  });

  it("derives status NOT_APPLICABLE when every rule is skipped", () => {
    const r = rule({
      rule_id: "K1",
      status: "skipped",
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "Prompt Injection" },
      ],
    });
    const out = buildComplianceShape([category([r])]);
    expect(out[0]!.controls[0]!.status).toBe("not_applicable");
  });

  it("derives status MET when one rule passed and another is skipped (mixed but no findings)", () => {
    // Honest semantic: a control where some rules ran and passed, some
    // could not run, is MET (we can attest to what we did test).
    // PARTIAL is reserved for "we tested and found below-threshold issues".
    // Choose your poison: this matches the compliance-reports default
    // where partial requires `findings`, not `skipped`.
    const r1 = rule({
      rule_id: "K1",
      status: "passed",
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "Prompt Injection" },
      ],
    });
    const r2 = rule({
      rule_id: "K2",
      status: "skipped",
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "Prompt Injection" },
      ],
    });
    const out = buildComplianceShape([category([r1, r2])]);
    expect(out[0]!.controls[0]!.status).toBe("met");
  });

  it("sorts frameworks alphabetically by id", () => {
    const r = rule({
      rule_id: "K1",
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "x" },
        { framework_id: "eu_ai_act", control_id: "Article 12", control_title: "y" },
        { framework_id: "iso_27001", control_id: "A.8.15", control_title: "z" },
      ],
    });
    const out = buildComplianceShape([category([r])]);
    expect(out.map((f) => f.framework_id)).toEqual([
      "eu_ai_act",
      "iso_27001",
      "owasp_mcp",
    ]);
  });

  it("uses friendly framework labels for known ids", () => {
    const r = rule({
      rule_id: "K1",
      framework_controls: [
        { framework_id: "eu_ai_act", control_id: "Article 12", control_title: "x" },
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "y" },
      ],
    });
    const out = buildComplianceShape([category([r])]);
    const labels = out.map((f) => f.framework_label);
    expect(labels).toContain("EU AI Act");
    expect(labels).toContain("OWASP MCP Top 10");
  });

  it("falls back to the framework_id when the label is unknown", () => {
    const r = rule({
      rule_id: "K1",
      framework_controls: [
        { framework_id: "future_framework_v9", control_id: "X1", control_title: "x" },
      ],
    });
    const out = buildComplianceShape([category([r])]);
    expect(out[0]!.framework_label).toBe("future_framework_v9");
  });

  it("sorts controls within a framework with numeric awareness (MCP02 before MCP10)", () => {
    const r1 = rule({
      rule_id: "K1",
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP10", control_title: "a" },
        { framework_id: "owasp_mcp", control_id: "MCP02", control_title: "b" },
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "c" },
      ],
    });
    const out = buildComplianceShape([category([r1])]);
    expect(out[0]!.controls.map((c) => c.control_id)).toEqual([
      "MCP01",
      "MCP02",
      "MCP10",
    ]);
  });

  it("dedupes a rule that appears across cross-referenced sub-categories", () => {
    const r = rule({
      rule_id: "K1",
      status: "passed",
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "x" },
      ],
    });
    // Same rule in two sub-categories — common via cross_references.
    const cat: DeepDiveCategory = {
      ...category([r]),
      sub_categories: [
        ...category([r]).sub_categories,
        {
          id: "z",
          title: "Z",
          summary: "",
          counts: {
            rules_total: 1,
            rules_passed: 0,
            rules_with_findings: 0,
            rules_skipped: 0,
            finding_count: 0,
            severity_breakdown: emptySev(),
          },
          rules: [r],
        },
      ],
    };
    const out = buildComplianceShape([cat]);
    expect(out[0]!.controls[0]!.rules.length).toBe(1);
  });

  it("computes per-framework counts (controls_met / unmet / partial / na)", () => {
    const passed = rule({
      rule_id: "K1",
      status: "passed",
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "x" },
      ],
    });
    const findingHigh = rule({
      rule_id: "K2",
      status: "findings",
      findings: [
        {
          id: "f1",
          severity: "high",
          confidence: 0.9,
          evidence: "x",
          evidence_chain: null,
          remediation: "y",
        },
      ],
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP02", control_title: "x" },
      ],
    });
    const findingMed = rule({
      rule_id: "K3",
      status: "findings",
      findings: [
        {
          id: "f2",
          severity: "medium",
          confidence: 0.5,
          evidence: "x",
          evidence_chain: null,
          remediation: "y",
        },
      ],
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP03", control_title: "x" },
      ],
    });
    const skipped = rule({
      rule_id: "K4",
      status: "skipped",
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP04", control_title: "x" },
      ],
    });
    const out = buildComplianceShape([
      category([passed, findingHigh, findingMed, skipped]),
    ]);
    const fw = out[0]!;
    expect(fw.counts).toEqual({
      controls_total: 4,
      controls_met: 1,
      controls_unmet: 1,
      controls_partial: 1,
      controls_not_applicable: 1,
    });
  });

  it("is byte-equal across runs for identical input (determinism contract)", () => {
    const r = rule({
      rule_id: "K1",
      status: "passed",
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "x" },
      ],
    });
    const a = buildComplianceShape([category([r])]);
    const b = buildComplianceShape([category([r])]);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });

  it("survives partial input (sub_categories / rules / framework_controls missing) without throwing", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const bad = (v: any) => v as any;
    const cats: DeepDiveCategory[] = [
      bad({ id: "x" }), // no sub_categories
      bad({ id: "y", sub_categories: [bad({ id: "z" })] }), // no rules
      bad({
        id: "w",
        sub_categories: [bad({ id: "z", rules: [bad({ rule_id: "K1" })] })],
      }), // no framework_controls
    ];
    expect(() => buildComplianceShape(cats)).not.toThrow();
    expect(buildComplianceShape(cats)).toEqual([]);
  });

  it("counts per-control rules_passed / rules_with_findings / rules_skipped / finding_count", () => {
    const passed = rule({
      rule_id: "K1",
      status: "passed",
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "x" },
      ],
    });
    const findings = rule({
      rule_id: "K2",
      status: "findings",
      findings: [
        {
          id: "a",
          severity: "high",
          confidence: 1,
          evidence: "",
          evidence_chain: null,
          remediation: "",
        },
        {
          id: "b",
          severity: "medium",
          confidence: 1,
          evidence: "",
          evidence_chain: null,
          remediation: "",
        },
      ],
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "x" },
      ],
    });
    const skipped = rule({
      rule_id: "K3",
      status: "skipped",
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "x" },
      ],
    });
    const out = buildComplianceShape([category([passed, findings, skipped])]);
    expect(out[0]!.controls[0]!.counts).toEqual({
      rules_total: 3,
      rules_passed: 1,
      rules_with_findings: 1,
      rules_skipped: 1,
      finding_count: 2,
    });
  });
});

// Compile-time guard — typedef must remain stable.
const _typeGuard: ComplianceFramework | null = null;
void _typeGuard;
