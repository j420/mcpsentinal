// @vitest-environment jsdom
/**
 * CoverageLedger smoke tests.
 *
 * Guards: skipped rules group by structured reason, the bucket headline +
 * action copy render correctly, the conversion CTA fires when source code
 * is missing, and no skipped rules → component renders nothing.
 */

import { describe, expect, it } from "vitest";
import React from "react";
import { render } from "@testing-library/react";
import CoverageLedger from "../components/CoverageLedger";
import type {
  DeepDiveCategory,
  DeepDiveCoverageSummary,
} from "../lib/deep-dive";

function emptySev(): DeepDiveCoverageSummary["severity_breakdown"] {
  return { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
}

function makeCoverage(
  overrides: Partial<DeepDiveCoverageSummary> = {},
): DeepDiveCoverageSummary {
  return {
    coverage_band: "medium",
    total_rules: 164,
    rules_executed: 142,
    rules_skipped_no_data: 22,
    rules_with_findings: 0,
    total_findings: 0,
    severity_breakdown: emptySev(),
    ...overrides,
  };
}

type DeepDiveRuleLike = DeepDiveCategory["sub_categories"][number]["rules"][number];

function makeSkipped(
  ruleId: string,
  name: string,
  inputs: Array<"source_code" | "connection" | "dependencies">,
  summary: string,
): DeepDiveRuleLike {
  return {
    rule_id: ruleId,
    name,
    severity: "high",
    category: "C",
    owasp: null,
    mitre: null,
    summary: "",
    framework_controls: [],
    methodology: {
      technique: "ast-taint",
      verified_edge_cases: [],
      edge_case_strategies: [],
      confidence_cap: null,
    },
    backing: null,
    remediation: "—",
    status: "skipped",
    findings: [],
    skip_reason: { missing_inputs: inputs, summary },
  };
}

function makeCategory(rules: DeepDiveRuleLike[]): DeepDiveCategory {
  return {
    id: "code-vulnerabilities",
    title: "Code Vulnerabilities",
    summary: "",
    frameworks: [],
    counts: {
      rules_total: rules.length,
      rules_passed: 0,
      rules_with_findings: 0,
      rules_skipped: rules.length,
      finding_count: 0,
      severity_breakdown: emptySev(),
    },
    sub_categories: [
      {
        id: "command-injection",
        title: "Command Injection",
        summary: "",
        counts: {
          rules_total: rules.length,
          rules_passed: 0,
          rules_with_findings: 0,
          rules_skipped: rules.length,
          finding_count: 0,
          severity_breakdown: emptySev(),
        },
        rules,
      },
    ],
  };
}

describe("CoverageLedger", () => {
  it("renders nothing when no rules are skipped", () => {
    const passedRule: DeepDiveRuleLike = {
      ...makeSkipped("X1", "x", ["source_code"], "x"),
      status: "passed",
      skip_reason: undefined,
    };
    const { container } = render(
      <CoverageLedger
        coverage={makeCoverage()}
        categories={[makeCategory([passedRule])]}
      />,
    );
    expect(container.querySelector(".cov-ledger")).toBeNull();
  });

  it("groups skipped rules by their structured missing_inputs set", () => {
    const c1 = makeSkipped(
      "C1",
      "Command Injection",
      ["source_code"],
      "source code not available for this server",
    );
    const c2 = makeSkipped(
      "C2",
      "Path Traversal",
      ["source_code"],
      "source code not available for this server",
    );
    const i3 = makeSkipped(
      "I3",
      "Resource Metadata Injection",
      ["connection"],
      "no live MCP connection during scan",
    );
    const cat = makeCategory([c1, c2, i3]);
    const { container } = render(
      <CoverageLedger
        coverage={makeCoverage({ had_source_code: false, had_connection: false })}
        categories={[cat]}
      />,
    );
    const buckets = container.querySelectorAll(".cov-bucket");
    expect(buckets.length).toBe(2);
    // Larger bucket (source_code, 2 rules) should come first.
    expect(buckets[0]!.textContent).toContain("source code");
    expect(buckets[0]!.textContent).toContain("C1");
    expect(buckets[0]!.textContent).toContain("C2");
    expect(buckets[1]!.textContent).toContain("MCP connection");
    expect(buckets[1]!.textContent).toContain("I3");
  });

  it("fires the conversion CTA when source_code is missing on coverage", () => {
    const c1 = makeSkipped("C1", "Command Injection", ["source_code"], "x");
    const cat = makeCategory([c1]);
    const { container } = render(
      <CoverageLedger
        coverage={makeCoverage({ had_source_code: false })}
        categories={[cat]}
      />,
    );
    expect(container.textContent).toMatch(/become testable/i);
  });

  it("does NOT fire the conversion CTA when source code IS already on file", () => {
    const i3 = makeSkipped("I3", "Resource", ["connection"], "no connection");
    const cat = makeCategory([i3]);
    const { container } = render(
      <CoverageLedger
        coverage={makeCoverage({ had_source_code: true })}
        categories={[cat]}
      />,
    );
    expect(container.textContent).not.toMatch(/become testable/i);
  });

  it("dedupes a rule that appears in multiple sub-categories (cross-references)", () => {
    const c1 = makeSkipped("C1", "Command Injection", ["source_code"], "x");
    const cat: DeepDiveCategory = {
      ...makeCategory([c1]),
      sub_categories: [
        ...makeCategory([c1]).sub_categories,
        {
          id: "shell-injection",
          title: "Shell Injection",
          summary: "",
          counts: {
            rules_total: 1,
            rules_passed: 0,
            rules_with_findings: 0,
            rules_skipped: 1,
            finding_count: 0,
            severity_breakdown: emptySev(),
          },
          rules: [c1],
        },
      ],
    };
    const { container } = render(
      <CoverageLedger
        coverage={makeCoverage({ had_source_code: false })}
        categories={[cat]}
      />,
    );
    const ruleLinks = container.querySelectorAll(".cov-bucket-rule");
    expect(ruleLinks.length).toBe(1);
  });
});
