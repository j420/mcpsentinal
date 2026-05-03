/**
 * Audit Summary derivation tests (Phase 4.2).
 *
 * Table-driven coverage of the deterministic decision functions inside
 * `audit-summary.ts`. Every branch of the recommendation engine fires at
 * least once; outcome / category-status / confidence / coverage-band
 * mappings each exercise their boundaries.
 */

import { describe, it, expect } from "vitest";
import {
  buildAuditSummary,
  deriveRecommendation,
  deriveOutcome,
  deriveCategoryStatus,
  deriveConfidence,
  mapCoverageBand,
  scoreBand,
} from "../audit-summary.js";
import type {
  AuditAttackIntelligence,
  AuditAttackScenario,
  AuditConfidence,
  AuditTestingDepth,
  DeepDiveCategory,
  Finding,
} from "@mcp-sentinel/database";
import type { DeepDiveAttackChain } from "../deep-dive.js";

// ─── Fixture helpers ─────────────────────────────────────────────────────────

function makeFinding(over: Partial<Finding> = {}): Finding {
  return {
    id: "11111111-1111-1111-1111-111111111111",
    server_id: "22222222-2222-2222-2222-222222222222",
    scan_id: "33333333-3333-3333-3333-333333333333",
    rule_id: "X1",
    severity: "low",
    evidence: "Sample evidence",
    remediation: "Sample remediation",
    owasp_category: null,
    mitre_technique: null,
    disputed: false,
    confidence: 1.0,
    evidence_chain: { links: [] },
    created_at: new Date(),
    ...over,
  } as Finding;
}

function makeChain(over: Partial<DeepDiveAttackChain> = {}): DeepDiveAttackChain {
  return {
    chain_id: "kc1-abc",
    kill_chain_id: "KC01",
    kill_chain_name: "KC01: Cross-server injection",
    steps: [
      { ordinal: 0, server_name: "Source MCP", role: "source", narrative: "n/a" },
      { ordinal: 1, server_name: "Sink MCP", role: "sink", narrative: "n/a" },
    ],
    exploitability_overall: 0.7,
    exploitability_rating: "high",
    narrative: "An attacker exfiltrates via the sink server.",
    mitigations: [],
    owasp_refs: [],
    mitre_refs: [],
    ...over,
  };
}

function makeScenario(over: Partial<AuditAttackScenario> = {}): AuditAttackScenario {
  return {
    chain_id: "kc1-abc",
    name: "KC01: Cross-server injection",
    narrative: "n/a",
    source: "Source MCP",
    propagation: [],
    sink: "Sink MCP",
    outcome: "NOT_OBSERVED",
    ...over,
  };
}

function makeCategory(over: Partial<DeepDiveCategory["counts"]> = {}): DeepDiveCategory {
  const counts: DeepDiveCategory["counts"] = {
    rules_total: 10,
    rules_passed: 10,
    rules_with_findings: 0,
    rules_skipped: 0,
    finding_count: 0,
    severity_breakdown: {
      critical: 0, high: 0, medium: 0, low: 0, informational: 0,
    },
    ...over,
  };
  return {
    id: "cat-1",
    title: "Sample category",
    summary: "n/a",
    frameworks: [],
    counts,
    sub_categories: [],
  } as DeepDiveCategory;
}

const BASE_DEPTH: AuditTestingDepth = {
  categories_tested: [],
  tests_executed: 100,
  tests_skipped_no_data: 0,
  inputs_available: { code: true, runtime: true, deps: true },
  coverage_level: "HIGH",
};

// ─── scoreBand boundaries ────────────────────────────────────────────────────

describe("scoreBand", () => {
  it.each([
    [80, "good"],
    [99, "good"],
    [100, "good"],
    [60, "moderate"],
    [79, "moderate"],
    [40, "poor"],
    [59, "poor"],
    [0, "critical"],
    [39, "critical"],
  ])("score %i → %s", (score, expected) => {
    expect(scoreBand(score)).toBe(expected);
  });
});

// ─── mapCoverageBand ─────────────────────────────────────────────────────────

describe("mapCoverageBand", () => {
  it.each([
    ["high", "HIGH"],
    ["medium", "MEDIUM"],
    ["low", "LOW"],
    ["minimal", "LOW"],
    [null, "LOW"],
  ] as const)("band %s → %s", (band, expected) => {
    expect(mapCoverageBand(band)).toBe(expected);
  });
});

// ─── deriveOutcome ───────────────────────────────────────────────────────────

describe("deriveOutcome", () => {
  it.each([
    ["critical", "VULNERABLE"],
    ["high", "VULNERABLE"],
    ["medium", "NOT_OBSERVED"],
    ["low", "BLOCKED"],
    ["unknown-rating", "NOT_OBSERVED"],
  ] as const)("rating %s → %s", (rating, expected) => {
    const chain = makeChain({ exploitability_rating: rating });
    expect(deriveOutcome(chain)).toBe(expected);
  });
});

// ─── deriveCategoryStatus ────────────────────────────────────────────────────

describe("deriveCategoryStatus", () => {
  it("returns SAFE when 0 findings AND at least one rule ran", () => {
    const cat = makeCategory({ rules_passed: 5, rules_with_findings: 0 });
    expect(deriveCategoryStatus(cat)).toBe("SAFE");
  });

  it("returns UNKNOWN when no rule ran (everything skipped)", () => {
    const cat = makeCategory({
      rules_passed: 0,
      rules_with_findings: 0,
      rules_skipped: 7,
    });
    expect(deriveCategoryStatus(cat)).toBe("UNKNOWN");
  });

  it("returns CAUTION on a critical finding", () => {
    const cat = makeCategory({
      rules_with_findings: 1,
      severity_breakdown: { critical: 1, high: 0, medium: 0, low: 0, informational: 0 },
    });
    expect(deriveCategoryStatus(cat)).toBe("CAUTION");
  });

  it("returns CAUTION on a high finding", () => {
    const cat = makeCategory({
      rules_with_findings: 1,
      severity_breakdown: { critical: 0, high: 2, medium: 0, low: 0, informational: 0 },
    });
    expect(deriveCategoryStatus(cat)).toBe("CAUTION");
  });

  it("returns CAUTION on a medium finding", () => {
    const cat = makeCategory({
      rules_with_findings: 1,
      severity_breakdown: { critical: 0, high: 0, medium: 1, low: 0, informational: 0 },
    });
    expect(deriveCategoryStatus(cat)).toBe("CAUTION");
  });

  it("returns SAFE when only low/informational findings present", () => {
    const cat = makeCategory({
      rules_passed: 4,
      rules_with_findings: 1,
      severity_breakdown: { critical: 0, high: 0, medium: 0, low: 3, informational: 2 },
    });
    expect(deriveCategoryStatus(cat)).toBe("SAFE");
  });
});

// ─── deriveConfidence ────────────────────────────────────────────────────────

describe("deriveConfidence", () => {
  const baseInput = {
    deepDive: { server: { slug: "s", name: "n" }, coverage: {} as never, categories: [] },
    score: {
      total_score: 80,
      coverage_band: "high" as const,
      analysis_coverage: {
        had_source_code: true,
        had_connection: true,
        had_dependencies: true,
        coverage_ratio: 1,
        techniques_run: [],
        rules_executed: 100,
        rules_skipped_no_data: 5,
      },
    },
    findings: [makeFinding({ evidence_chain: { links: [] } })],
  };

  it("returns HIGH when coverage HIGH + chains preserved + skip < 0.1", () => {
    const conf = deriveConfidence(baseInput, { ...BASE_DEPTH, coverage_level: "HIGH" });
    expect(conf.level).toBe("HIGH");
  });

  it("returns LOW when skip ratio crosses 0.5", () => {
    const conf = deriveConfidence(
      {
        ...baseInput,
        score: {
          ...baseInput.score!,
          analysis_coverage: {
            ...baseInput.score!.analysis_coverage!,
            rules_executed: 30,
            rules_skipped_no_data: 70,
          },
        },
      },
      { ...BASE_DEPTH, coverage_level: "MEDIUM" },
    );
    expect(conf.level).toBe("LOW");
  });

  it("returns LOW when coverage_level is LOW even with low skip ratio", () => {
    const conf = deriveConfidence(baseInput, { ...BASE_DEPTH, coverage_level: "LOW" });
    expect(conf.level).toBe("LOW");
  });

  it("returns MEDIUM in the in-between zone", () => {
    const conf = deriveConfidence(
      {
        ...baseInput,
        score: {
          ...baseInput.score!,
          analysis_coverage: {
            ...baseInput.score!.analysis_coverage!,
            rules_executed: 80,
            rules_skipped_no_data: 20,
          },
        },
      },
      { ...BASE_DEPTH, coverage_level: "MEDIUM" },
    );
    expect(conf.level).toBe("MEDIUM");
  });

  it("demotes a HIGH band to MEDIUM when a chain is missing on a finding", () => {
    const conf = deriveConfidence(
      {
        ...baseInput,
        findings: [makeFinding({ evidence_chain: null })],
      },
      { ...BASE_DEPTH, coverage_level: "HIGH" },
    );
    // chains_preserved=false breaks the HIGH precondition → MEDIUM
    expect(conf.level).toBe("MEDIUM");
  });
});

// ─── deriveRecommendation — every decision branch ────────────────────────────

describe("deriveRecommendation", () => {
  const baseInput = {
    deepDive: { server: { slug: "s", name: "n" }, coverage: {} as never, categories: [] },
    score: {
      total_score: 90,
      coverage_band: "high" as const,
      analysis_coverage: {
        had_source_code: true,
        had_connection: true,
        had_dependencies: true,
        coverage_ratio: 1,
        techniques_run: [],
        rules_executed: 100,
        rules_skipped_no_data: 0,
      },
    },
    findings: [] as Finding[],
  };
  const highConf: AuditConfidence = { level: "HIGH", factors: [] };
  const mediumConf: AuditConfidence = { level: "MEDIUM", factors: [] };
  const lowConf: AuditConfidence = { level: "LOW", factors: [] };
  const emptyIntel: AuditAttackIntelligence = { scenarios: [] };

  it("Rule 1 — critical VULNERABLE chain → NO", () => {
    const intel: AuditAttackIntelligence = {
      scenarios: [makeScenario({ outcome: "VULNERABLE", name: "KC01: Critical exploit" })],
    };
    const r = deriveRecommendation(baseInput, intel, highConf);
    expect(r.use_in_production).toBe("NO");
    expect(r.rationale.join(" ")).toMatch(/active critical exploit chain/i);
  });

  it("Rule 2 — F1 lethal trifecta → NO", () => {
    const r = deriveRecommendation(
      { ...baseInput, findings: [makeFinding({ rule_id: "F1", severity: "high" })] },
      emptyIntel,
      highConf,
    );
    expect(r.use_in_production).toBe("NO");
    expect(r.rationale.join(" ")).toMatch(/lethal trifecta/i);
  });

  it("Rule 3 — score < 40 → NO", () => {
    const r = deriveRecommendation(
      { ...baseInput, score: { ...baseInput.score!, total_score: 30 } },
      emptyIntel,
      highConf,
    );
    expect(r.use_in_production).toBe("NO");
    expect(r.rationale.some((x) => /critical band/i.test(x))).toBe(true);
  });

  it("Rule 4 — score < 60 → CONDITIONAL with conditions", () => {
    const r = deriveRecommendation(
      {
        ...baseInput,
        score: { ...baseInput.score!, total_score: 50 },
        findings: [
          makeFinding({ severity: "high", rule_id: "X1", evidence: "Issue 1" }),
          makeFinding({ severity: "high", rule_id: "X2", evidence: "Issue 2" }),
        ],
      },
      emptyIntel,
      highConf,
    );
    expect(r.use_in_production).toBe("CONDITIONAL");
    expect(r.conditions.length).toBeGreaterThan(0);
  });

  it("Rule 5 — non-critical VULNERABLE chain → CONDITIONAL", () => {
    const intel: AuditAttackIntelligence = {
      scenarios: [makeScenario({ outcome: "VULNERABLE", name: "KC02: High exploit" })],
    };
    const r = deriveRecommendation(baseInput, intel, highConf);
    expect(r.use_in_production).toBe("CONDITIONAL");
  });

  it("Rule 6 — coverage LOW → CONDITIONAL with re-scan conditions", () => {
    const r = deriveRecommendation(
      {
        ...baseInput,
        score: {
          ...baseInput.score!,
          coverage_band: "low",
          analysis_coverage: {
            ...baseInput.score!.analysis_coverage!,
            had_source_code: false,
            had_connection: false,
          },
        },
      },
      emptyIntel,
      mediumConf,
    );
    expect(r.use_in_production).toBe("CONDITIONAL");
    expect(r.conditions.some((c) => /source code/i.test(c))).toBe(true);
    expect(r.conditions.some((c) => /MCP connection/i.test(c))).toBe(true);
  });

  it("Rule 7 — confidence LOW → CONDITIONAL", () => {
    const r = deriveRecommendation(baseInput, emptyIntel, lowConf);
    expect(r.use_in_production).toBe("CONDITIONAL");
    expect(r.rationale.some((x) => /confidence LOW/i.test(x))).toBe(true);
  });

  it("Rule 8 — clean baseline → YES", () => {
    const r = deriveRecommendation(baseInput, emptyIntel, highConf);
    expect(r.use_in_production).toBe("YES");
    expect(r.conditions).toEqual([]);
    expect(r.rationale.length).toBeGreaterThan(0);
  });

  it("tie-breaker — score=39 + lethal trifecta → NO with both rationales", () => {
    const r = deriveRecommendation(
      {
        ...baseInput,
        score: { ...baseInput.score!, total_score: 39 },
        findings: [makeFinding({ rule_id: "F1", severity: "critical" })],
      },
      emptyIntel,
      highConf,
    );
    expect(r.use_in_production).toBe("NO");
    expect(r.rationale.some((x) => /lethal trifecta/i.test(x))).toBe(true);
    expect(r.rationale.some((x) => /critical band/i.test(x))).toBe(true);
  });

  it("disclaimer is always present", () => {
    const r = deriveRecommendation(baseInput, emptyIntel, highConf);
    expect(r.disclaimer.length).toBeGreaterThan(0);
  });
});

// ─── buildAuditSummary — happy-path integration ──────────────────────────────

describe("buildAuditSummary", () => {
  it("renders a complete audit summary on a clean server", () => {
    const summary = buildAuditSummary({
      deepDive: {
        server: { slug: "clean-server", name: "Clean Server" },
        coverage: {
          coverage_band: "high",
          total_rules: 100,
          rules_executed: 100,
          rules_skipped_no_data: 0,
          rules_with_findings: 0,
          total_findings: 0,
          severity_breakdown: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
        },
        categories: [makeCategory({ rules_passed: 10, rules_with_findings: 0 })],
      } as never,
      score: {
        total_score: 95,
        coverage_band: "high",
        analysis_coverage: {
          had_source_code: true,
          had_connection: true,
          had_dependencies: true,
          coverage_ratio: 1,
          techniques_run: ["ast-taint"],
          rules_executed: 100,
          rules_skipped_no_data: 0,
        },
      },
      findings: [],
    });

    expect(summary.verdict.pill).toBe("SAFE");
    expect(summary.verdict.score).toBe(95);
    expect(summary.verdict.band).toBe("good");
    expect(summary.recommendation.use_in_production).toBe("YES");
    expect(summary.testing_depth.coverage_level).toBe("HIGH");
    expect(summary.confidence.level).toBe("HIGH");
    expect(summary.evidence_trust.runtime_analysis).toBe(true);
    expect(summary.evidence_trust.e2e_chain_preserved).toBe(true);
    expect(summary.gaps).toEqual([]);
  });

  it("renders an honest verdict when score is missing entirely", () => {
    const summary = buildAuditSummary({
      deepDive: {
        server: { slug: "no-scan", name: "Never Scanned" },
        coverage: {
          coverage_band: null,
          total_rules: 0, rules_executed: 0, rules_skipped_no_data: 0,
          rules_with_findings: 0, total_findings: 0,
          severity_breakdown: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
        },
        categories: [],
      } as never,
      score: null,
      findings: [],
    });

    expect(summary.verdict.score).toBe(0);
    expect(summary.verdict.band).toBe("critical");
    expect(summary.verdict.pill).toBe("RISK");
    // Score 0 → Rule 3 fires → NO
    expect(summary.recommendation.use_in_production).toBe("NO");
  });
});
