// @vitest-environment jsdom
/**
 * EvidenceSummaryHero v6 coverage upgrade — test suite.
 *
 * Asserts the four new affordances added when score_detail carries
 * coverage_band / v2_sub_scores / analysis_coverage:
 *   1. Confidence chip beside the score column (high/medium/low/minimal).
 *   2. Three "what we analysed" pips (source / live / deps) with check / × glyphs.
 *   3. 8-bucket v2 sub-score row (schema, ecosystem, protocol, adversarial,
 *      compliance, supply-chain, infrastructure, code).
 *   4. Inline "X of Y rules executed" meta line.
 *
 * Backwards-compat: when all three coverage fields are null the hero MUST
 * render exactly as it did before — no chip, no pips, no sub-score row, no
 * coverage meta line.
 */
import { describe, it, expect } from "vitest";
import React from "react";
import { render } from "@testing-library/react";
import EvidenceSummaryHero from "../components/EvidenceSummaryHero";

// ── Fixtures ────────────────────────────────────────────────────────────────

type CoverageBand = "high" | "medium" | "low" | "minimal";

interface V2SubScores {
  schema_score: number;
  ecosystem_score: number;
  protocol_score: number;
  adversarial_score: number;
  compliance_score: number;
  supply_chain_score: number;
  infrastructure_score: number;
  code_score: number;
}

interface AnalysisCoverage {
  had_source_code: boolean;
  had_connection: boolean;
  had_dependencies: boolean;
  coverage_ratio: number;
  techniques_run: string[];
  rules_executed: number;
  rules_skipped_no_data: number;
}

interface ScoreDetail {
  total_score: number;
  coverage_band?: CoverageBand | null;
  v2_sub_scores?: V2SubScores | null;
  analysis_coverage?: AnalysisCoverage | null;
}

function makeBaseProps() {
  return {
    name: "demo-mcp-server",
    description: "Test fixture description",
    author: "test-author",
    license: "MIT",
    server_version: "1.0.0",
    endpoint_url: null,
    github_url: null,
    npm_package: null,
    pypi_package: null,
    last_scanned_at: "2026-04-30T10:00:00Z",
    scan_stages: null,
    findings: [] as Array<{
      rule_id: string;
      severity: "critical" | "high" | "medium" | "low" | "informational";
      evidence: string;
    }>,
    tools: [] as Array<{ name: string; capability_tags: string[] }>,
  };
}

function makeFullV2SubScores(): V2SubScores {
  return {
    schema_score: 92,
    ecosystem_score: 85,
    protocol_score: 78,
    adversarial_score: 64,
    compliance_score: 51,
    supply_chain_score: 42,
    infrastructure_score: 33,
    code_score: 21,
  };
}

function makeFullCoverage(overrides: Partial<AnalysisCoverage> = {}): AnalysisCoverage {
  return {
    had_source_code: true,
    had_connection: true,
    had_dependencies: true,
    coverage_ratio: 0.95,
    techniques_run: ["ast-taint", "capability-graph", "entropy"],
    rules_executed: 158,
    rules_skipped_no_data: 6,
    ...overrides,
  };
}

function makeScoreDetail(over: Partial<ScoreDetail> = {}): ScoreDetail {
  return {
    total_score: 72,
    coverage_band: "high",
    v2_sub_scores: makeFullV2SubScores(),
    analysis_coverage: makeFullCoverage(),
    ...over,
  };
}

// ═════════════════════════════════════════════════════════════════════════════
// Coverage band chip
// ═════════════════════════════════════════════════════════════════════════════

describe("coverage band chip", () => {
  it("coverage_band='high' → 'HIGH confidence' chip with --good color", () => {
    const { container, getByText } = render(
      <EvidenceSummaryHero
        {...makeBaseProps()}
        score_detail={makeScoreDetail({ coverage_band: "high" })}
      />
    );
    const chip = container.querySelector(".esh-cov-chip-high") as HTMLElement | null;
    expect(chip).not.toBeNull();
    expect(getByText(/HIGH confidence/i)).toBeTruthy();
    // Inline style maps to --good token (high band)
    expect(chip!.getAttribute("style") ?? "").toContain("var(--good)");
    // Accessible label
    expect(chip!.getAttribute("aria-label")).toMatch(/high/i);
  });

  it("coverage_band='medium' → MEDIUM chip with --moderate color", () => {
    const { container, getByText } = render(
      <EvidenceSummaryHero
        {...makeBaseProps()}
        score_detail={makeScoreDetail({ coverage_band: "medium" })}
      />
    );
    const chip = container.querySelector(".esh-cov-chip-medium") as HTMLElement | null;
    expect(chip).not.toBeNull();
    expect(getByText(/MEDIUM confidence/i)).toBeTruthy();
    expect(chip!.getAttribute("style") ?? "").toContain("var(--moderate)");
  });

  it("coverage_band='low' → LOW chip with --poor color", () => {
    const { container, getByText } = render(
      <EvidenceSummaryHero
        {...makeBaseProps()}
        score_detail={makeScoreDetail({ coverage_band: "low" })}
      />
    );
    const chip = container.querySelector(".esh-cov-chip-low") as HTMLElement | null;
    expect(chip).not.toBeNull();
    expect(getByText(/LOW confidence/i)).toBeTruthy();
    expect(chip!.getAttribute("style") ?? "").toContain("var(--poor)");
  });

  it("coverage_band='minimal' → MINIMAL chip with --critical color", () => {
    const { container, getByText } = render(
      <EvidenceSummaryHero
        {...makeBaseProps()}
        score_detail={makeScoreDetail({ coverage_band: "minimal" })}
      />
    );
    const chip = container.querySelector(".esh-cov-chip-minimal") as HTMLElement | null;
    expect(chip).not.toBeNull();
    expect(getByText(/MINIMAL confidence/i)).toBeTruthy();
    expect(chip!.getAttribute("style") ?? "").toContain("var(--critical)");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Backwards compatibility — null coverage fields → legacy rendering
// ═════════════════════════════════════════════════════════════════════════════

describe("backwards compatibility (legacy scans)", () => {
  it("null analysis_coverage AND null v2_sub_scores → no chip, no pips, no sub-score row, no coverage meta line", () => {
    const { container } = render(
      <EvidenceSummaryHero
        {...makeBaseProps()}
        score_detail={{
          total_score: 72,
          coverage_band: null,
          v2_sub_scores: null,
          analysis_coverage: null,
        }}
      />
    );
    // No coverage cluster (chip + pips group) at all
    expect(container.querySelector(".esh-cov-cluster")).toBeNull();
    // No confidence chip
    expect(container.querySelector(".esh-cov-chip")).toBeNull();
    // No pips
    expect(container.querySelector(".esh-cov-pips")).toBeNull();
    // No 8-bucket row
    expect(container.querySelector(".esh-cov-subscores")).toBeNull();
    // No "X of Y rules executed" meta
    expect(container.querySelector('[data-testid="esh-cov-rules-executed"]')).toBeNull();
    // Existing legacy structure intact
    expect(container.querySelector(".esh-hero")).not.toBeNull();
    expect(container.querySelector(".esh-col-score")).not.toBeNull();
    expect(container.querySelector(".esh-col-identity")).not.toBeNull();
    expect(container.querySelector(".esh-col-meta")).not.toBeNull();
    expect(container.textContent).toContain("72");
  });

  it("score_detail itself is null → still no coverage UI, hero renders", () => {
    const { container } = render(
      <EvidenceSummaryHero
        {...makeBaseProps()}
        score_detail={null}
      />
    );
    expect(container.querySelector(".esh-cov-cluster")).toBeNull();
    expect(container.querySelector(".esh-cov-subscores")).toBeNull();
    expect(container.querySelector(".esh-hero")).not.toBeNull();
    // — placeholder when score is unknown
    expect(container.textContent).toContain("—");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// "What we analysed" pips
// ═════════════════════════════════════════════════════════════════════════════

describe('"what we analysed" pips', () => {
  it("had_source_code=false → source pip muted with × glyph; live + deps remain ✓", () => {
    const { container } = render(
      <EvidenceSummaryHero
        {...makeBaseProps()}
        score_detail={makeScoreDetail({
          analysis_coverage: makeFullCoverage({ had_source_code: false }),
        })}
      />
    );
    const pips = container.querySelectorAll(".esh-cov-pip");
    expect(pips.length).toBe(3);

    // source pip should be off
    const sourcePip = container.querySelector('[aria-label^="source:"]') as HTMLElement | null;
    expect(sourcePip).not.toBeNull();
    expect(sourcePip!.classList.contains("esh-cov-pip-off")).toBe(true);
    expect(sourcePip!.getAttribute("aria-label")).toContain("missing");
    // × glyph (×) present in the off pip
    expect(sourcePip!.textContent).toContain("×");

    // live + deps remain ✓
    const livePip = container.querySelector('[aria-label^="live:"]') as HTMLElement | null;
    const depsPip = container.querySelector('[aria-label^="deps:"]') as HTMLElement | null;
    expect(livePip!.classList.contains("esh-cov-pip-on")).toBe(true);
    expect(depsPip!.classList.contains("esh-cov-pip-on")).toBe(true);
    expect(livePip!.textContent).toContain("✓"); // ✓
    expect(depsPip!.textContent).toContain("✓");

    // Each pip has a meaningful title for accessibility
    expect(sourcePip!.getAttribute("title") ?? "").toMatch(/source code/i);
    expect(livePip!.getAttribute("title") ?? "").toMatch(/initialize/i);
    expect(depsPip!.getAttribute("title") ?? "").toMatch(/depend/i);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 8-bucket v2 sub-score row
// ═════════════════════════════════════════════════════════════════════════════

describe("8-bucket v2 sub-score row", () => {
  it("v2_sub_scores → renders all 8 buckets with labels + numeric values in fixed order", () => {
    const subs = makeFullV2SubScores();
    const { container } = render(
      <EvidenceSummaryHero
        {...makeBaseProps()}
        score_detail={makeScoreDetail({ v2_sub_scores: subs })}
      />
    );
    const list = container.querySelector(".esh-cov-subscores") as HTMLElement | null;
    expect(list).not.toBeNull();
    // dl semantics: 8 dt + 8 dd
    const dts = list!.querySelectorAll("dt");
    const dds = list!.querySelectorAll("dd");
    expect(dts.length).toBe(8);
    expect(dds.length).toBe(8);

    // Fixed display order
    const labelsInOrder = Array.from(dts).map((n) => n.textContent?.trim());
    expect(labelsInOrder).toEqual([
      "Schema",
      "Ecosystem",
      "Protocol",
      "Adversarial",
      "Compliance",
      "Supply chain",
      "Infrastructure",
      "Code",
    ]);

    // Values rendered, in same order
    const valuesInOrder = Array.from(dds).map((n) => n.textContent?.trim());
    expect(valuesInOrder).toEqual([
      String(subs.schema_score),
      String(subs.ecosystem_score),
      String(subs.protocol_score),
      String(subs.adversarial_score),
      String(subs.compliance_score),
      String(subs.supply_chain_score),
      String(subs.infrastructure_score),
      String(subs.code_score),
    ]);

    // Each row carries a data-bucket so styling/scripting can target by key
    const buckets = Array.from(list!.querySelectorAll(".esh-cov-subscore")).map(
      (n) => n.getAttribute("data-bucket"),
    );
    expect(buckets).toEqual([
      "schema_score",
      "ecosystem_score",
      "protocol_score",
      "adversarial_score",
      "compliance_score",
      "supply_chain_score",
      "infrastructure_score",
      "code_score",
    ]);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// "X of Y rules executed" meta line
// ═════════════════════════════════════════════════════════════════════════════

describe('"X of Y rules executed" meta', () => {
  it("analysis_coverage present → meta line rendered with executed + skipped sum", () => {
    const cov = makeFullCoverage({
      rules_executed: 142,
      rules_skipped_no_data: 22,
    });
    const { container } = render(
      <EvidenceSummaryHero
        {...makeBaseProps()}
        score_detail={makeScoreDetail({ analysis_coverage: cov })}
      />
    );
    const row = container.querySelector(
      '[data-testid="esh-cov-rules-executed"]',
    ) as HTMLElement | null;
    expect(row).not.toBeNull();
    expect(row!.textContent).toContain("142 of 164 rules executed");
  });
});
