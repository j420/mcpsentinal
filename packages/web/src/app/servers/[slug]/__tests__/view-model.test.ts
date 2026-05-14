import { describe, it, expect } from "vitest";
import { buildViewModel } from "../view-model";
import type {
  DeepDiveData,
  DeepDiveRule,
  DeepDiveFinding,
} from "@/lib/deep-dive";

// ── Fixture builders (tiny, no `any`) ─────────────────────────────────

function finding(
  overrides: Partial<DeepDiveFinding> & { severity: DeepDiveFinding["severity"] },
): DeepDiveFinding {
  return {
    id: overrides.id ?? `f-${Math.random().toString(36).slice(2, 8)}`,
    severity: overrides.severity,
    confidence: overrides.confidence ?? 0.9,
    evidence: overrides.evidence ?? "evidence prose",
    evidence_chain: overrides.evidence_chain ?? null,
    remediation: overrides.remediation ?? "fix it",
  };
}

function rule(
  id: string,
  status: DeepDiveRule["status"],
  findings: DeepDiveFinding[] = [],
  overrides: Partial<DeepDiveRule> = {},
): DeepDiveRule {
  return {
    rule_id: id,
    name: overrides.name ?? `Rule ${id}`,
    severity: overrides.severity ?? findings[0]?.severity ?? "medium",
    category: overrides.category ?? "code-analysis",
    owasp: overrides.owasp ?? null,
    mitre: overrides.mitre ?? null,
    summary: overrides.summary ?? "summary",
    framework_controls: overrides.framework_controls ?? [],
    methodology: overrides.methodology ?? {
      technique: "ast-taint",
      verified_edge_cases: [],
      edge_case_strategies: [],
      confidence_cap: null,
    },
    backing: overrides.backing ?? null,
    remediation: overrides.remediation ?? "fix it",
    status,
    findings,
    ...overrides,
  };
}

function dataOf(rules: DeepDiveRule[]): DeepDiveData {
  return {
    server: { slug: "test", name: "Test" },
    coverage: {
      coverage_band: "high",
      total_rules: rules.length,
      rules_executed: rules.length,
      rules_skipped_no_data: rules.filter((r) => r.status === "skipped").length,
      rules_with_findings: rules.filter((r) => r.status === "findings").length,
      total_findings: rules.reduce((n, r) => n + r.findings.length, 0),
      severity_breakdown: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        informational: 0,
      },
    },
    categories: [
      {
        id: "code-vulnerabilities",
        title: "Code Vulnerabilities",
        summary: "",
        frameworks: ["MCP03"],
        counts: {
          rules_total: rules.length,
          rules_passed: rules.filter((r) => r.status === "passed").length,
          rules_with_findings: rules.filter((r) => r.status === "findings").length,
          rules_skipped: rules.filter((r) => r.status === "skipped").length,
          finding_count: rules.reduce((n, r) => n + r.findings.length, 0),
          severity_breakdown: {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            informational: 0,
          },
        },
        sub_categories: [
          {
            id: "command-injection",
            title: "Command Injection",
            summary: "",
            counts: {
              rules_total: rules.length,
              rules_passed: rules.filter((r) => r.status === "passed").length,
              rules_with_findings: rules.filter((r) => r.status === "findings").length,
              rules_skipped: rules.filter((r) => r.status === "skipped").length,
              finding_count: rules.reduce((n, r) => n + r.findings.length, 0),
              severity_breakdown: {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                informational: 0,
              },
            },
            rules,
          },
        ],
      },
    ],
  };
}

// ── Tests ─────────────────────────────────────────────────────────────

describe("buildViewModel — partition", () => {
  it("partitions rules into findings / skipped / passed buckets", () => {
    const data = dataOf([
      rule("C1", "findings", [finding({ severity: "high" })]),
      rule("C2", "passed"),
      rule("C3", "skipped", [], {
        skip_reason: { missing_inputs: ["source_code"], summary: "no source" },
      }),
    ]);
    const vm = buildViewModel(data);
    expect(vm.counts).toEqual({ findings: 1, skipped: 1, passed: 1, total: 3 });
    expect(vm.findingsByCategory).toHaveLength(1);
    expect(vm.findingsByCategory[0].subCategories[0].rules).toHaveLength(1);
    expect(vm.skipped).toHaveLength(1);
    expect(vm.skipped[0].missingInputs).toEqual(["source_code"]);
  });

  it("filters retired rules out of every bucket", () => {
    const data = dataOf([
      rule("O1", "skipped"), // retired
      rule("M3", "findings", [finding({ severity: "critical" })]), // retired
      rule("C1", "findings", [finding({ severity: "high" })]), // live
    ]);
    const vm = buildViewModel(data);
    expect(vm.counts.findings).toBe(1);
    expect(vm.counts.skipped).toBe(0);
    const ruleIds = vm.findingsByCategory[0].subCategories[0].rules.map(
      (r) => r.rule_id,
    );
    expect(ruleIds).toEqual(["C1"]);
  });

  it("drops non-canonical placements (is_canonical === false)", () => {
    const data = dataOf([
      rule("C1", "findings", [finding({ severity: "high" })]),
      rule("C1", "findings", [finding({ severity: "high" })], {
        is_canonical: false,
      }),
    ]);
    const vm = buildViewModel(data);
    expect(vm.findingsByCategory[0].subCategories[0].rules).toHaveLength(1);
  });

  it("classifies a category as clean when it has no findings", () => {
    const data = dataOf([rule("C1", "passed"), rule("C2", "passed")]);
    const vm = buildViewModel(data);
    expect(vm.findingsByCategory).toHaveLength(0);
    expect(vm.cleanCategories).toHaveLength(1);
    expect(vm.cleanCategories[0].id).toBe("code-vulnerabilities");
  });
});

describe("buildViewModel — score + verdict", () => {
  it("scores 100 / SAFE / good with no findings", () => {
    const vm = buildViewModel(dataOf([rule("C1", "passed")]));
    expect(vm.score).toBe(100);
    expect(vm.verdict).toBe("SAFE");
    expect(vm.band).toBe("good");
  });

  it("deducts per severity weight", () => {
    const vm = buildViewModel(
      dataOf([
        rule("C1", "findings", [finding({ severity: "high" })]),
        rule("C2", "findings", [finding({ severity: "medium" })]),
      ]),
    );
    // 100 − 15 − 8 = 77
    expect(vm.score).toBe(77);
    expect(vm.verdict).toBe("CAUTION");
  });

  it("emits RISK verdict when any critical finding is present", () => {
    const vm = buildViewModel(
      dataOf([rule("C1", "findings", [finding({ severity: "critical" })])]),
    );
    expect(vm.verdict).toBe("RISK");
  });

  it("caps score at 40 when F1 (lethal trifecta) fires", () => {
    const vm = buildViewModel(
      dataOf([
        rule("F1", "findings", [finding({ severity: "critical" })]),
      ]),
    );
    expect(vm.score).toBe(40);
    expect(vm.lethalTrifectaActive).toBe(true);
  });

  it("floors at 0 — never negative", () => {
    const findings = Array.from({ length: 10 }, () =>
      finding({ severity: "critical" }),
    );
    const vm = buildViewModel(dataOf([rule("C1", "findings", findings)]));
    expect(vm.score).toBe(0);
  });
});

describe("buildViewModel — ordering", () => {
  it("sorts rules within a sub-category by worst severity first", () => {
    const data = dataOf([
      rule("C1", "findings", [finding({ severity: "low" })]),
      rule("C2", "findings", [finding({ severity: "critical" })]),
      rule("C3", "findings", [finding({ severity: "medium" })]),
    ]);
    const vm = buildViewModel(data);
    const ids = vm.findingsByCategory[0].subCategories[0].rules.map(
      (r) => r.rule_id,
    );
    expect(ids).toEqual(["C2", "C3", "C1"]);
  });

  it("computes worstSeverity on each rule from its findings", () => {
    const data = dataOf([
      rule("C1", "findings", [
        finding({ severity: "low" }),
        finding({ severity: "high" }),
      ]),
    ]);
    const vm = buildViewModel(data);
    expect(vm.findingsByCategory[0].subCategories[0].rules[0].worstSeverity).toBe(
      "high",
    );
  });
});

describe("buildViewModel — skipped grouping", () => {
  it("groups skipped rules by the set of missing inputs", () => {
    const data = dataOf([
      rule("D1", "skipped", [], {
        skip_reason: { missing_inputs: ["dependencies"], summary: "" },
      }),
      rule("C1", "skipped", [], {
        skip_reason: { missing_inputs: ["source_code"], summary: "" },
      }),
      rule("C2", "skipped", [], {
        skip_reason: { missing_inputs: ["source_code"], summary: "" },
      }),
    ]);
    const vm = buildViewModel(data);
    expect(vm.skipped).toHaveLength(2);
    const sourceGroup = vm.skipped.find((g) =>
      g.missingInputs.includes("source_code"),
    );
    expect(sourceGroup?.rules.map((r) => r.rule.rule_id)).toEqual(["C1", "C2"]);
  });

  it("returns no skipped groups when nothing is skipped", () => {
    const vm = buildViewModel(
      dataOf([rule("C1", "findings", [finding({ severity: "low" })])]),
    );
    expect(vm.skipped).toEqual([]);
  });
});

describe("buildViewModel — empty / null defenses", () => {
  it("handles empty categories array", () => {
    const vm = buildViewModel({
      server: { slug: "t", name: "T" },
      coverage: {
        coverage_band: null,
        total_rules: 0,
        rules_executed: 0,
        rules_skipped_no_data: 0,
        rules_with_findings: 0,
        total_findings: 0,
        severity_breakdown: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          informational: 0,
        },
      },
      categories: [],
    });
    expect(vm.findingsByCategory).toEqual([]);
    expect(vm.cleanCategories).toEqual([]);
    expect(vm.score).toBe(100);
    expect(vm.verdict).toBe("SAFE");
  });

  it("ignores nulls in nested arrays", () => {
    const malformed = {
      server: { slug: "t", name: "T" },
      coverage: {
        coverage_band: null,
        total_rules: 1,
        rules_executed: 1,
        rules_skipped_no_data: 0,
        rules_with_findings: 1,
        total_findings: 1,
        severity_breakdown: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          informational: 0,
        },
      },
      categories: [
        null,
        {
          id: "x",
          title: "X",
          summary: "",
          frameworks: [],
          counts: {
            rules_total: 0,
            rules_passed: 0,
            rules_with_findings: 0,
            rules_skipped: 0,
            finding_count: 0,
            severity_breakdown: {
              critical: 0,
              high: 0,
              medium: 0,
              low: 0,
              informational: 0,
            },
          },
          sub_categories: [null],
        },
      ],
    } as unknown as DeepDiveData;
    expect(() => buildViewModel(malformed)).not.toThrow();
  });
});
