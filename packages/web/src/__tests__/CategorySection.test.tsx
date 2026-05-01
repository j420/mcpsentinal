// @vitest-environment jsdom
/**
 * CategorySection — header chrome + sub-category fan-out + xref resolver.
 *
 * What this guards:
 *   1. Anchor id="cat-<id>" on the section.
 *   2. Title renders as <h2>.
 *   3. Framework chips list renders one chip per declared framework.
 *   4. Aggregate counts line reads "<tested> of <total> rules tested · <evidence>".
 *   5. Severity breakdown bar renders one segment per non-zero severity,
 *      with proportional width and aria-label.
 *   6. The cross-reference resolver: when rule_id appears in two
 *      sub-categories, the second one renders the xref form (one card,
 *      not two; one xref link, not none).
 */

import { describe, it, expect, afterEach } from "vitest";
import React from "react";
import { cleanup, render } from "@testing-library/react";
import CategorySection from "../components/CategorySection";

afterEach(() => cleanup());
import type {
  DeepDiveCategory,
  DeepDiveSubCategory,
  DeepDiveRule,
} from "../lib/deep-dive";

function makeRule(rule_id: string, overrides: Partial<DeepDiveRule> = {}): DeepDiveRule {
  return {
    rule_id,
    name: `Rule ${rule_id}`,
    severity: "medium",
    category: "ecosystem-context",
    owasp: null,
    mitre: null,
    summary: `Summary for ${rule_id}`,
    framework_controls: [],
    methodology: {
      technique: "capability-graph",
      verified_edge_cases: [],
      edge_case_strategies: [],
      confidence_cap: null,
    },
    backing: { fixture_count: 0, cve_replay_ids: [], precision: null, recall: null, last_validated_at: null },
    remediation: "fix it",
    status: "passed",
    findings: [],
    ...overrides,
  };
}

function makeSub(id: string, rules: DeepDiveRule[]): DeepDiveSubCategory {
  return {
    id,
    title: id,
    summary: `Sub ${id}`,
    counts: {
      rules_total: rules.length,
      rules_passed: rules.length,
      rules_with_findings: 0,
      rules_skipped: 0,
      finding_count: 0,
      severity_breakdown: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
    },
    rules,
  };
}

function makeCategory(overrides: Partial<DeepDiveCategory> = {}): DeepDiveCategory {
  return {
    id: "ecosystem",
    title: "Ecosystem & Cross-Tool Risk",
    summary: "Capability-graph risk patterns and lethal trifectas.",
    frameworks: ["OWASP MCP", "MITRE ATLAS"],
    counts: {
      rules_total: 4,
      rules_passed: 2,
      rules_with_findings: 1,
      rules_skipped: 1,
      finding_count: 3,
      severity_breakdown: { critical: 1, high: 1, medium: 1, low: 0, informational: 0 },
    },
    sub_categories: [
      makeSub("sub-trifecta", [makeRule("F1"), makeRule("F2")]),
      makeSub("sub-data-flow", [makeRule("F3"), makeRule("F4")]),
    ],
    ...overrides,
  };
}

describe("CategorySection", () => {
  it("renders the cat anchor id on the <section>", () => {
    const { container } = render(<CategorySection cat={makeCategory()} />);
    const section = container.querySelector("#cat-ecosystem");
    expect(section).not.toBeNull();
    expect(section?.tagName).toBe("SECTION");
  });

  it("renders the title as <h2>", () => {
    const { container } = render(<CategorySection cat={makeCategory()} />);
    expect(container.querySelector("h2.cs-title")?.textContent).toBe("Ecosystem & Cross-Tool Risk");
  });

  it("renders one chip per framework", () => {
    const { container } = render(<CategorySection cat={makeCategory()} />);
    const chips = container.querySelectorAll(".cs-fw-chip");
    expect(chips.length).toBe(2);
    expect(Array.from(chips).map((c) => c.textContent)).toEqual(["OWASP MCP", "MITRE ATLAS"]);
  });

  it("renders the aggregate counts line", () => {
    const { container } = render(<CategorySection cat={makeCategory()} />);
    const agg = container.querySelector(".cs-aggregate-text");
    expect(agg?.textContent ?? "").toMatch(/3 of 4 rule.*tested/);
    expect(agg?.textContent ?? "").toMatch(/3 finding/);
    expect(agg?.textContent ?? "").toMatch(/1 skipped/);
  });

  it("renders one severity-bar segment per non-zero severity, with aria-label", () => {
    const { container } = render(<CategorySection cat={makeCategory()} />);
    const bar = container.querySelector(".cs-sev-bar");
    expect(bar).not.toBeNull();
    expect(bar?.getAttribute("role")).toBe("img");
    expect(bar?.getAttribute("aria-label") ?? "").toMatch(/critical/);
    // 3 non-zero severities: critical, high, medium.
    const segs = container.querySelectorAll(".cs-sev-bar-seg");
    expect(segs.length).toBe(3);
    expect(container.querySelector(".cs-sev-bar-seg-critical")).not.toBeNull();
    expect(container.querySelector(".cs-sev-bar-seg-high")).not.toBeNull();
    expect(container.querySelector(".cs-sev-bar-seg-medium")).not.toBeNull();
    expect(container.querySelector(".cs-sev-bar-seg-low")).toBeNull();
  });

  it("renders an honest 'no findings' bar when severity_breakdown is all zero", () => {
    const cat = makeCategory({
      counts: {
        rules_total: 4,
        rules_passed: 4,
        rules_with_findings: 0,
        rules_skipped: 0,
        finding_count: 0,
        severity_breakdown: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
      },
    });
    const { container } = render(<CategorySection cat={cat} />);
    const bar = container.querySelector(".cs-sev-bar-empty");
    expect(bar).not.toBeNull();
    expect(bar?.textContent ?? "").toMatch(/no findings/);
  });

  it("demotes a duplicate rule_id to xref form on its second appearance", () => {
    // F1 appears in both sub-trifecta and sub-data-flow.
    const cat = makeCategory({
      sub_categories: [
        makeSub("sub-trifecta", [makeRule("F1"), makeRule("F2")]),
        makeSub("sub-data-flow", [makeRule("F1"), makeRule("F4")]),
      ],
    });
    const { container } = render(<CategorySection cat={cat} />);
    // F1 should render canonically once, and as xref once.
    const f1Cards = container.querySelectorAll("#rule-F1");
    expect(f1Cards.length).toBe(1);
    const xrefs = container.querySelectorAll(".rec-xref");
    expect(xrefs.length).toBe(1);
    const xrefLink = xrefs[0].querySelector(".rec-xref-link");
    expect(xrefLink?.getAttribute("href")).toBe("#rule-F1");
  });
});
