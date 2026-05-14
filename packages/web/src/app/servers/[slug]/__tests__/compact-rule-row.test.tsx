import React from "react";
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import CompactRuleRow from "../compact-rule-row";
import type { CascadeRule } from "../view-model";

afterEach(() => cleanup());

function makeRule(overrides: Partial<CascadeRule> = {}): CascadeRule {
  return {
    rule_id: "C2",
    name: "Path Traversal",
    severity: "high",
    category: "code-analysis",
    owasp: "MCP03",
    mitre: null,
    summary: "Detects unsafe path joins.",
    framework_controls: [],
    methodology: {
      technique: "ast-taint",
      verified_edge_cases: [],
      edge_case_strategies: ["sanitizer-verified-by-name", "taint-path-strict"],
      confidence_cap: 0.95,
    },
    backing: null,
    remediation: "Resolve and confine.",
    status: "passed",
    worstSeverity: null,
    findings: [],
    ...overrides,
  };
}

describe("CompactRuleRow — passed", () => {
  it("renders a compact summary row with id, name, and Passed status", () => {
    const { container } = render(<CompactRuleRow rule={makeRule()} />);
    expect(screen.getByText("C2")).toBeInTheDocument();
    expect(screen.getByText("Path Traversal")).toBeInTheDocument();
    expect(screen.getByText("Passed")).toBeInTheDocument();
    expect(screen.getByText("Tested cleanly")).toBeInTheDocument();
    const root = container.querySelector(".fv-crow");
    expect(root).toHaveAttribute("data-status", "passed");
    expect((root as HTMLDetailsElement | null)?.open).toBe(false);
  });

  it("reveals the TESTS panel + 'Tested cleanly' callout when expanded", () => {
    const { container } = render(<CompactRuleRow rule={makeRule()} />);
    // The body is server-rendered inside the <details>; it's always in
    // the DOM regardless of the `open` attribute.
    expect(screen.getByText("Tests")).toBeInTheDocument();
    expect(screen.getByText("sanitizer-verified-by-name")).toBeInTheDocument();
    expect(screen.getByText("taint-path-strict")).toBeInTheDocument();
    expect(
      screen.getByText(/Tested cleanly — no evidence of this attack vector/i),
    ).toBeInTheDocument();
    expect(container.querySelector(".fv-rule-clean")).toBeInTheDocument();
  });
});

describe("CompactRuleRow — skipped", () => {
  const skipped = makeRule({
    rule_id: "K9",
    name: "Dangerous Post-Install Hooks",
    status: "skipped",
    skip_reason: {
      missing_inputs: ["source_code"],
      summary: "Source code not yet ingested for this server.",
    },
  });

  it("renders a 'Skipped' status row and shows missing inputs in the hint", () => {
    const { container } = render(<CompactRuleRow rule={skipped} />);
    expect(screen.getByText("Skipped")).toBeInTheDocument();
    expect(screen.getByText(/Needs Source code/i)).toBeInTheDocument();
    const root = container.querySelector(".fv-crow");
    expect(root).toHaveAttribute("data-status", "skipped");
  });

  it("reveals the skip-reason callout with labeled 'Needs · …' CTA on expand", () => {
    const { container } = render(<CompactRuleRow rule={skipped} />);
    expect(screen.getByText(/Source code not yet ingested/i)).toBeInTheDocument();
    expect(screen.getByText(/Needs · Source code/i)).toBeInTheDocument();
    expect(
      screen.getByText(/Add a GitHub URL to your server registration/i),
    ).toBeInTheDocument();
    expect(container.querySelector(".fv-rule-skipped")).toBeInTheDocument();
  });

  it("still surfaces the TESTS panel for skipped rules", () => {
    render(<CompactRuleRow rule={skipped} />);
    expect(screen.getByText("Tests")).toBeInTheDocument();
    expect(screen.getByText("sanitizer-verified-by-name")).toBeInTheDocument();
  });
});
