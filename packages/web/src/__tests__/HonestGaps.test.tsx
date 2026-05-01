// @vitest-environment jsdom
/**
 * HonestGaps Test Suite — packages/web/src/components/HonestGaps.tsx
 *
 * What this guards:
 *   1. Full coverage object renders all dynamic rows correctly + the
 *      coverage_band chip lights up green (high band).
 *   2. analysis_coverage = null still renders the static gaps + a muted
 *      chip + the "coverage data unavailable" fallback (resilience over
 *      perfection — page never blocks because of a missing field).
 *   3. had_source_code: false renders the source row with × and a muted
 *      "not fetched" descriptor.
 *   4. All four band variants resolve to the correct CSS class on the
 *      chip (good/moderate/poor/critical).
 *   5. ASI10 disclosure ALWAYS renders, irrespective of input — regression
 *      guard for the "honest gaps must remain visible" requirement.
 */

import { describe, it, expect } from "vitest";
import React from "react";
import { render } from "@testing-library/react";
import HonestGaps, { type HonestGapsCoverage } from "../components/HonestGaps";

// ── Fixtures ────────────────────────────────────────────────────────────

function makeCoverage(over: Partial<HonestGapsCoverage> = {}): HonestGapsCoverage {
  return {
    had_source_code: true,
    had_connection: true,
    had_dependencies: true,
    coverage_ratio: 0.92,
    techniques_run: ["ast-taint", "entropy", "capability-graph"],
    rules_executed: 142,
    rules_skipped_no_data: 22,
    ...over,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// 1. Full coverage object → all dynamic rows + green band chip
// ═══════════════════════════════════════════════════════════════════════

describe("full coverage object", () => {
  it("renders source / connection / dependencies as ✓ with descriptive text", () => {
    const { container } = render(
      <HonestGaps analysis_coverage={makeCoverage()} findingsCount={3} />,
    );
    const okRows = container.querySelectorAll(".hg-row-ok");
    // 3 dynamic OK rows: source, connection, dependencies
    expect(okRows).toHaveLength(3);
    const text = container.textContent ?? "";
    expect(text).toContain("Source code");
    expect(text).toContain("Live connection");
    expect(text).toContain("Dependencies");
    // Each dynamic row carries a ✓
    const checks = Array.from(okRows).filter((r) =>
      (r.textContent ?? "").includes("✓"),
    );
    expect(checks).toHaveLength(3);
  });

  it("coverage_band chip is hg-band-good for full coverage", () => {
    const { container } = render(
      <HonestGaps analysis_coverage={makeCoverage()} findingsCount={3} />,
    );
    expect(container.querySelector(".hg-band-good")).not.toBeNull();
    // Negative checks — only ONE band class is applied.
    expect(container.querySelector(".hg-band-moderate")).toBeNull();
    expect(container.querySelector(".hg-band-poor")).toBeNull();
    expect(container.querySelector(".hg-band-critical")).toBeNull();
    expect(container.querySelector(".hg-band-unknown")).toBeNull();
    expect(container.textContent).toContain("HIGH coverage");
  });

  it("renders rules executed / total + skipped breakdown", () => {
    const { container } = render(
      <HonestGaps
        analysis_coverage={makeCoverage({ rules_executed: 142, rules_skipped_no_data: 22 })}
        findingsCount={5}
      />,
    );
    const text = container.textContent ?? "";
    expect(text).toContain("142");
    expect(text).toContain("164"); // 142 + 22
    expect(text).toContain("22");
    expect(text).toContain("skipped");
  });

  it("renders the techniques_run footer when techniques are present", () => {
    const { container } = render(
      <HonestGaps
        analysis_coverage={makeCoverage({ techniques_run: ["ast-taint", "entropy"] })}
        findingsCount={1}
      />,
    );
    expect(container.textContent).toContain("ast-taint");
    expect(container.textContent).toContain("entropy");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 2. analysis_coverage = null → renders + static gaps + muted chip
// ═══════════════════════════════════════════════════════════════════════

describe("null coverage", () => {
  it("still renders the card (does not return null/empty)", () => {
    const { container } = render(
      <HonestGaps analysis_coverage={null} findingsCount={0} />,
    );
    expect(container.querySelector(".hg-card")).not.toBeNull();
  });

  it("shows the coverage_band chip in the muted (unknown) variant", () => {
    const { container } = render(
      <HonestGaps analysis_coverage={null} findingsCount={0} />,
    );
    expect(container.querySelector(".hg-band-unknown")).not.toBeNull();
    expect(container.querySelector(".hg-band-good")).toBeNull();
  });

  it("dynamic rows degrade to 'coverage data unavailable'", () => {
    const { container } = render(
      <HonestGaps analysis_coverage={null} findingsCount={0} />,
    );
    const text = container.textContent ?? "";
    // Three dynamic rows fall through; "coverage data unavailable"
    // appears at least three times (source / connection / dependencies)
    // plus once on the rules-executed fallback row.
    const occurrences = text.match(/coverage data unavailable/g);
    expect(occurrences).not.toBeNull();
    expect((occurrences ?? []).length).toBeGreaterThanOrEqual(3);
  });

  it("static rows still render (dynamic-tester, retired rules, ASI10)", () => {
    const { container } = render(
      <HonestGaps analysis_coverage={null} findingsCount={0} />,
    );
    const text = container.textContent ?? "";
    expect(text).toContain("Dynamic invocation tests");
    expect(text).toContain("ADR-007");
    expect(text).toContain("Retired rules");
    expect(text).toContain("13 disabled");
    expect(text).toContain("ASI10");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 3. had_source_code: false → row shows × and muted text
// ═══════════════════════════════════════════════════════════════════════

describe("had_source_code = false", () => {
  it("source row renders × marker and a 'not fetched' descriptor", () => {
    const { container } = render(
      <HonestGaps
        analysis_coverage={makeCoverage({
          had_source_code: false,
          coverage_ratio: 0.55,
        })}
        findingsCount={2}
      />,
    );
    // The source row is the first dynamic StatusRow; we identify it by
    // searching for the row whose label is "Source code".
    const rows = container.querySelectorAll(".hg-row");
    const sourceRow = Array.from(rows).find((r) =>
      (r.querySelector(".hg-row-label")?.textContent ?? "") === "Source code",
    );
    expect(sourceRow).toBeDefined();
    expect(sourceRow!.classList.contains("hg-row-miss")).toBe(true);
    expect(sourceRow!.textContent).toContain("×");
    expect(sourceRow!.textContent).toContain("not fetched");
  });

  it("downgrades the band away from 'high' when source code missing", () => {
    const { container } = render(
      <HonestGaps
        analysis_coverage={makeCoverage({
          had_source_code: false,
          coverage_ratio: 0.95, // high ratio but missing source → not 'high'
        })}
        findingsCount={2}
      />,
    );
    // 0.95 with source missing must NOT resolve to high (band derivation
    // requires both source AND connection AND ratio>=0.80).
    expect(container.querySelector(".hg-band-good")).toBeNull();
    // 0.95 still resolves to medium (>=0.60).
    expect(container.querySelector(".hg-band-moderate")).not.toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 4. All four band variants
// ═══════════════════════════════════════════════════════════════════════

describe("band derivation — all four variants", () => {
  it("high — ratio >= 0.80 + source + connection", () => {
    const { container } = render(
      <HonestGaps
        analysis_coverage={makeCoverage({ coverage_ratio: 0.85 })}
        findingsCount={1}
      />,
    );
    expect(container.querySelector(".hg-band-good")).not.toBeNull();
  });

  it("medium — ratio >= 0.60 (and not high)", () => {
    const { container } = render(
      <HonestGaps
        analysis_coverage={makeCoverage({ coverage_ratio: 0.65 })}
        findingsCount={1}
      />,
    );
    expect(container.querySelector(".hg-band-moderate")).not.toBeNull();
    expect(container.querySelector(".hg-band-good")).toBeNull();
  });

  it("low — ratio >= 0.30 (and not medium/high)", () => {
    const { container } = render(
      <HonestGaps
        analysis_coverage={makeCoverage({ coverage_ratio: 0.35 })}
        findingsCount={1}
      />,
    );
    expect(container.querySelector(".hg-band-poor")).not.toBeNull();
    expect(container.querySelector(".hg-band-moderate")).toBeNull();
  });

  it("minimal — ratio < 0.30", () => {
    const { container } = render(
      <HonestGaps
        analysis_coverage={makeCoverage({ coverage_ratio: 0.10 })}
        findingsCount={1}
      />,
    );
    expect(container.querySelector(".hg-band-critical")).not.toBeNull();
    expect(container.querySelector(".hg-band-poor")).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 5. ASI10 disclosure regression guard
// ═══════════════════════════════════════════════════════════════════════

describe("ASI10 disclosure (regression guard)", () => {
  it("renders ASI10 honest-gap row when coverage is full", () => {
    const { container } = render(
      <HonestGaps analysis_coverage={makeCoverage()} findingsCount={5} />,
    );
    expect(container.querySelector("[data-test-asi10]")).not.toBeNull();
    const text = container.textContent ?? "";
    expect(text).toContain("ASI10");
    expect(text).toContain("Agentic Data Poisoning");
    expect(text).toContain("not assessable");
  });

  it("renders ASI10 honest-gap row when coverage is null", () => {
    const { container } = render(
      <HonestGaps analysis_coverage={null} findingsCount={0} />,
    );
    expect(container.querySelector("[data-test-asi10]")).not.toBeNull();
    expect(container.textContent).toContain("ASI10");
  });

  it("renders ASI10 honest-gap row even on minimal-coverage scans", () => {
    const { container } = render(
      <HonestGaps
        analysis_coverage={makeCoverage({
          had_source_code: false,
          had_connection: false,
          had_dependencies: false,
          coverage_ratio: 0.05,
          techniques_run: [],
          rules_executed: 8,
          rules_skipped_no_data: 156,
        })}
        findingsCount={0}
      />,
    );
    expect(container.querySelector("[data-test-asi10]")).not.toBeNull();
    expect(container.textContent).toContain("ASI10");
  });
});
