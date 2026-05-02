import { describe, expect, it } from "vitest";
import {
  buildAutoNarrative,
  buildVerdictHeadline,
  type AutoNarrativeInput,
} from "@/lib/auto-narrative";
import type {
  DeepDiveAttackChain,
  DeepDiveCategory,
  DeepDiveCoverageSummary,
} from "@/lib/deep-dive";

function emptySev(): DeepDiveCoverageSummary["severity_breakdown"] {
  return { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
}

function makeCoverage(
  overrides: Partial<DeepDiveCoverageSummary> = {},
): DeepDiveCoverageSummary {
  return {
    coverage_band: "high",
    total_rules: 164,
    rules_executed: 142,
    rules_skipped_no_data: 22,
    rules_with_findings: 0,
    total_findings: 0,
    severity_breakdown: emptySev(),
    ...overrides,
  };
}

function makeChain(
  overrides: Partial<DeepDiveAttackChain> = {},
): DeepDiveAttackChain {
  return {
    chain_id: "abc123",
    kill_chain_id: "KC01",
    kill_chain_name: "Indirect Injection → Data Exfiltration",
    steps: [{ ordinal: 1 }, { ordinal: 2 }, { ordinal: 3 }],
    exploitability_overall: 0.75,
    exploitability_rating: "critical",
    narrative: "...",
    mitigations: [],
    owasp_refs: [],
    mitre_refs: [],
    ...overrides,
  };
}

function makeCategory(
  overrides: Partial<DeepDiveCategory> = {},
): DeepDiveCategory {
  return {
    id: "code-vulnerabilities",
    title: "Code Vulnerabilities",
    summary: "",
    frameworks: [],
    counts: {
      rules_total: 0,
      rules_passed: 0,
      rules_with_findings: 0,
      rules_skipped: 0,
      finding_count: 0,
      severity_breakdown: emptySev(),
    },
    sub_categories: [],
    ...overrides,
  };
}

describe("buildAutoNarrative", () => {
  it("returns no bullets when input is fully empty", () => {
    const out = buildAutoNarrative({
      coverage: undefined,
      categories: undefined,
      attackChains: undefined,
    });
    expect(out).toEqual([]);
  });

  it("emits a critical-findings bullet when severity_breakdown.critical > 0", () => {
    const out = buildAutoNarrative({
      coverage: makeCoverage({
        rules_with_findings: 4,
        severity_breakdown: { ...emptySev(), critical: 2, high: 5 },
        total_findings: 7,
        rules_skipped_no_data: 0,
      }),
      categories: [],
      attackChains: [],
    });
    const ids = out.map((b) => b.id);
    expect(ids).toContain("critical-findings");
    const bullet = out.find((b) => b.id === "critical-findings")!;
    expect(bullet.tone).toBe("critical");
    expect(bullet.text).toContain("2 critical findings");
    expect(bullet.text).toContain("5 high-severity findings");
  });

  it("prefers critical-findings over high-findings when both are present", () => {
    const out = buildAutoNarrative({
      coverage: makeCoverage({
        rules_with_findings: 3,
        severity_breakdown: { ...emptySev(), critical: 1, high: 3 },
        total_findings: 4,
        rules_skipped_no_data: 0,
      }),
      categories: [],
      attackChains: [],
    });
    const ids = out.map((b) => b.id);
    expect(ids).toContain("critical-findings");
    expect(ids).not.toContain("high-findings");
  });

  it("emits a kill-chain bullet referencing the worst chain by exploitability", () => {
    const a = makeChain({
      chain_id: "a",
      exploitability_overall: 0.5,
      exploitability_rating: "high",
    });
    const b = makeChain({
      chain_id: "b",
      kill_chain_id: "KC03",
      kill_chain_name: "Credential Harvesting Chain",
      exploitability_overall: 0.9,
      exploitability_rating: "critical",
    });
    const out = buildAutoNarrative({
      coverage: makeCoverage(),
      categories: [],
      attackChains: [a, b],
    });
    const bullet = out.find((b) => b.id === "kill-chain")!;
    expect(bullet).toBeDefined();
    expect(bullet.text).toContain("KC03");
    expect(bullet.text).toContain("3 steps");
    expect(bullet.tone).toBe("critical");
  });

  it("emits a coverage-gap bullet when rules_skipped_no_data > 0", () => {
    const out = buildAutoNarrative({
      coverage: makeCoverage({
        rules_skipped_no_data: 22,
      }),
      categories: [],
      attackChains: [],
    });
    expect(out.some((b) => b.id === "coverage-gap")).toBe(true);
  });

  it("celebrates a clean server when coverage is high and no skips", () => {
    const out = buildAutoNarrative({
      coverage: makeCoverage({
        rules_executed: 164,
        rules_skipped_no_data: 0,
        rules_with_findings: 0,
        total_findings: 0,
        coverage_band: "high",
      }),
      categories: [],
      attackChains: [],
    });
    expect(out.some((b) => b.id === "clean-server")).toBe(true);
  });

  it("falls back to a clean-category celebration when not fully clean", () => {
    const cleanCat = makeCategory({
      id: "audit-logging",
      title: "Audit & Logging",
      counts: {
        rules_total: 5,
        rules_passed: 5,
        rules_with_findings: 0,
        rules_skipped: 0,
        finding_count: 0,
        severity_breakdown: emptySev(),
      },
    });
    const findingsCat = makeCategory({
      id: "code-vulnerabilities",
      counts: {
        rules_total: 5,
        rules_passed: 0,
        rules_with_findings: 5,
        rules_skipped: 0,
        finding_count: 8,
        severity_breakdown: { ...emptySev(), critical: 1, high: 4 },
      },
    });
    const out = buildAutoNarrative({
      coverage: makeCoverage({
        total_findings: 8,
        rules_with_findings: 5,
        severity_breakdown: { ...emptySev(), critical: 1, high: 4 },
      }),
      categories: [cleanCat, findingsCat],
      attackChains: [],
    });
    const cc = out.find((b) => b.id === "clean-category");
    expect(cc).toBeDefined();
    expect(cc!.text).toContain("Audit & Logging");
    expect(cc!.tone).toBe("good");
  });

  it("caps output at 5 bullets even when many fire", () => {
    const out = buildAutoNarrative({
      coverage: makeCoverage({
        total_findings: 20,
        rules_with_findings: 10,
        rules_skipped_no_data: 22,
        severity_breakdown: { ...emptySev(), critical: 5, high: 10 },
      }),
      categories: [
        makeCategory({
          id: "lethal-trifecta",
          counts: {
            rules_total: 1,
            rules_passed: 0,
            rules_with_findings: 1,
            rules_skipped: 0,
            finding_count: 1,
            severity_breakdown: { ...emptySev(), critical: 1 },
          },
        }),
        makeCategory({
          id: "audit-logging",
          counts: {
            rules_total: 5,
            rules_passed: 5,
            rules_with_findings: 0,
            rules_skipped: 0,
            finding_count: 0,
            severity_breakdown: emptySev(),
          },
        }),
      ],
      attackChains: [makeChain()],
    });
    expect(out.length).toBeLessThanOrEqual(5);
  });

  it("is byte-equal across runs for identical input (determinism contract)", () => {
    const input: AutoNarrativeInput = {
      coverage: makeCoverage({
        total_findings: 3,
        rules_with_findings: 3,
        severity_breakdown: { ...emptySev(), critical: 1, high: 2 },
      }),
      categories: [],
      attackChains: [makeChain()],
    };
    const a = buildAutoNarrative(input);
    const b = buildAutoNarrative(input);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});

describe("buildVerdictHeadline", () => {
  it("falls back to 'Awaiting scan data' when nothing on file", () => {
    const v = buildVerdictHeadline({
      coverage: undefined,
      categories: undefined,
      attackChains: undefined,
    });
    expect(v.text.toLowerCase()).toContain("awaiting");
    expect(v.tone).toBe("info");
  });

  it("leads with critical when critical findings exist", () => {
    const v = buildVerdictHeadline({
      coverage: makeCoverage({
        total_findings: 1,
        rules_with_findings: 1,
        severity_breakdown: { ...emptySev(), critical: 1 },
      }),
      categories: [],
      attackChains: [],
    });
    expect(v.tone).toBe("critical");
    expect(v.text.startsWith("Critical")).toBe(true);
  });

  it("leads with critical when a critical kill chain exists even with no findings", () => {
    const v = buildVerdictHeadline({
      coverage: makeCoverage(),
      categories: [],
      attackChains: [makeChain()],
    });
    expect(v.tone).toBe("critical");
    expect(v.text).toContain("KC01");
  });

  it("celebrates clean server when no findings and high coverage band", () => {
    const v = buildVerdictHeadline({
      coverage: makeCoverage({
        rules_executed: 164,
        rules_skipped_no_data: 0,
        coverage_band: "high",
      }),
      categories: [],
      attackChains: [],
    });
    expect(v.tone).toBe("good");
    expect(v.text.toLowerCase()).toContain("clean");
  });
});
