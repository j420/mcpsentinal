// @vitest-environment jsdom
/**
 * SubCategorySection — header + counts + per-rule fan-out.
 *
 * What this guards:
 *   1. Anchor `id="sub-<id>"` on the section.
 *   2. Title (h3) renders.
 *   3. Counts line ("X of Y rules tested · Z findings") matches the
 *      DeepDiveCounts contract.
 *   4. Each rule renders a RuleEvidenceCard (one card per rule).
 *   5. Cross-referenced rule_ids render in cross-ref mode (the small
 *      "see canonical" link rather than the full card).
 */

import { describe, it, expect, afterEach } from "vitest";
import React from "react";
import { cleanup, render } from "@testing-library/react";
import SubCategorySection from "../components/SubCategorySection";
import type { DeepDiveSubCategory, DeepDiveRule } from "../lib/deep-dive";

afterEach(() => cleanup());

function makeRule(rule_id: string, overrides: Partial<DeepDiveRule> = {}): DeepDiveRule {
  return {
    rule_id,
    name: `Rule ${rule_id}`,
    severity: "medium",
    category: "schema-analysis",
    owasp: null,
    mitre: null,
    summary: `Summary for ${rule_id}.`,
    framework_controls: [],
    methodology: "schema inspection",
    backing: {
      red_team_fixture_count: 4,
      cve_ids: [],
      last_validated_at: "2026-04-30T09:00:00.000Z",
      last_validation_pass: true,
    },
    remediation: "fix it",
    status: "passed",
    findings: [],
    ...overrides,
  };
}

function makeSub(overrides: Partial<DeepDiveSubCategory> = {}): DeepDiveSubCategory {
  return {
    id: "sub-prompt-injection",
    title: "Prompt Injection",
    summary: "Inputs that hijack the LLM via tool descriptions or content.",
    counts: {
      rules_total: 3,
      rules_passed: 2,
      rules_with_findings: 1,
      rules_skipped: 0,
      finding_count: 2,
      severity_breakdown: {
        critical: 1,
        high: 0,
        medium: 1,
        low: 0,
        informational: 0,
      },
    },
    rules: [makeRule("A1"), makeRule("A2"), makeRule("A3")],
    ...overrides,
  };
}

describe("SubCategorySection", () => {
  it("renders the sub anchor id on the <section>", () => {
    const { container } = render(<SubCategorySection sub={makeSub()} />);
    const section = container.querySelector("#sub-sub-prompt-injection");
    expect(section).not.toBeNull();
    expect(section?.tagName).toBe("SECTION");
  });

  it("renders the title as <h3>", () => {
    const { container } = render(<SubCategorySection sub={makeSub()} />);
    const h3 = container.querySelector("h3.scs-title");
    expect(h3?.textContent).toBe("Prompt Injection");
  });

  it("renders a counts line summarising rules + findings", () => {
    const { container } = render(<SubCategorySection sub={makeSub()} />);
    const counts = container.querySelector(".scs-counts");
    expect(counts?.textContent ?? "").toMatch(/3 of 3 rule.*tested/);
    expect(counts?.textContent ?? "").toMatch(/2 findings/);
  });

  it("renders one card per rule (canonical mode)", () => {
    const { container } = render(<SubCategorySection sub={makeSub()} />);
    expect(container.querySelectorAll(".rec-card").length).toBe(3);
    expect(container.querySelector("#rule-A1")).not.toBeNull();
    expect(container.querySelector("#rule-A2")).not.toBeNull();
    expect(container.querySelector("#rule-A3")).not.toBeNull();
  });

  it("demotes cross-referenced rules to the one-line xref form", () => {
    const xref = new Set<string>(["A2"]);
    const { container } = render(
      <SubCategorySection sub={makeSub()} crossReferencedRuleIds={xref} />,
    );
    // Two full cards (A1, A3), one xref line (A2).
    expect(container.querySelectorAll(".rec-card").length).toBe(2);
    const xrefBlocks = container.querySelectorAll(".rec-xref");
    expect(xrefBlocks.length).toBe(1);
    const link = xrefBlocks[0].querySelector(".rec-xref-link");
    expect(link?.getAttribute("href")).toBe("#rule-A2");
  });

  it("renders the 'all clean' evidence label when no findings and nothing skipped", () => {
    const sub = makeSub({
      counts: {
        rules_total: 3,
        rules_passed: 3,
        rules_with_findings: 0,
        rules_skipped: 0,
        finding_count: 0,
        severity_breakdown: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
      },
    });
    const { container } = render(<SubCategorySection sub={sub} />);
    expect(container.querySelector(".scs-counts")?.textContent ?? "").toMatch(/all clean/);
  });
});
