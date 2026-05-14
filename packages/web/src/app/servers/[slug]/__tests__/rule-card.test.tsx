import React from "react";
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import RuleCard from "../rule-card";
import type { CascadeRule } from "../view-model";

afterEach(() => cleanup());

function makeRule(overrides: Partial<CascadeRule> = {}): CascadeRule {
  return {
    rule_id: "C1",
    name: "Command Injection",
    severity: "critical",
    category: "code-analysis",
    owasp: "MCP03",
    mitre: "AML.T0054",
    summary: "exec() with user input",
    framework_controls: [],
    methodology: {
      technique: "ast-taint",
      verified_edge_cases: [],
      edge_case_strategies: ["sanitizer-verified-by-name", "deep-pass-through"],
      confidence_cap: 0.95,
    },
    backing: null,
    remediation: "Use execFile with array args.",
    status: "findings",
    worstSeverity: "critical",
    findings: [
      {
        id: "fin-1",
        severity: "critical",
        confidence: 0.91,
        evidence: "exec(req.query.cmd)",
        evidence_chain: null,
        remediation: "Use execFile.",
      },
    ],
    ...overrides,
  };
}

describe("RuleCard — findings state", () => {
  it("renders rule id, name, severity pill, and OWASP/MITRE chips", () => {
    render(<RuleCard rule={makeRule()} />);
    expect(screen.getByText("C1")).toBeInTheDocument();
    expect(screen.getByText("Command Injection")).toBeInTheDocument();
    expect(screen.getByText("MCP03")).toBeInTheDocument();
    expect(screen.getByText("AML.T0054")).toBeInTheDocument();
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("renders the severity rail keyed on worstSeverity", () => {
    const { container } = render(<RuleCard rule={makeRule()} />);
    const card = container.querySelector(".fv-rule");
    expect(card).toHaveAttribute("data-severity", "critical");
    expect(card).toHaveAttribute("data-status", "findings");
  });

  it("renders the TESTS panel inline with humanized titles + raw ids", () => {
    render(<RuleCard rule={makeRule()} />);
    expect(screen.getByText("Tests")).toBeInTheDocument();
    expect(screen.getByText("sanitizer-verified-by-name")).toBeInTheDocument();
    expect(screen.getByText("deep-pass-through")).toBeInTheDocument();
    expect(screen.getByText("Primary technique")).toBeInTheDocument();
    expect(screen.getByText("ast-taint")).toBeInTheDocument();
    expect(screen.getByText(/Sanitiser verification/i)).toBeInTheDocument();
  });

  it("renders the EVIDENCE panel with the structured chain fallback", () => {
    render(<RuleCard rule={makeRule()} />);
    expect(screen.getByText("Evidence")).toBeInTheDocument();
    // findings count appears in the section count
    const evidenceHead = screen
      .getByText("Evidence")
      .closest("header");
    expect(evidenceHead).not.toBeNull();
    expect(evidenceHead?.textContent).toMatch(/1 finding/);
    // prose fallback surfaces since the test chain is null
    expect(screen.getByText("exec(req.query.cmd)")).toBeInTheDocument();
  });

  it("renders per-finding remediation 'Fix' aside", () => {
    render(<RuleCard rule={makeRule()} />);
    expect(screen.getByText("Fix")).toBeInTheDocument();
    expect(screen.getByText("Use execFile.")).toBeInTheDocument();
  });
});

describe("RuleCard — passed state", () => {
  const passed = makeRule({
    rule_id: "C2",
    name: "Path Traversal",
    status: "passed",
    findings: [],
    worstSeverity: null,
  });

  it("renders a 'Passed' status pill and a green data-status rail", () => {
    const { container } = render(<RuleCard rule={passed} />);
    expect(screen.getByText("Passed")).toBeInTheDocument();
    const card = container.querySelector(".fv-rule");
    expect(card).toHaveAttribute("data-status", "passed");
  });

  it("still renders the TESTS panel — tests visible for every status", () => {
    render(<RuleCard rule={passed} />);
    expect(screen.getByText("Tests")).toBeInTheDocument();
    expect(screen.getByText("sanitizer-verified-by-name")).toBeInTheDocument();
  });

  it("renders the 'Tested cleanly' Evidence panel (not the chain)", () => {
    const { container } = render(<RuleCard rule={passed} />);
    expect(
      screen.getByText(/Tested cleanly — no evidence of this attack vector/i),
    ).toBeInTheDocument();
    expect(container.querySelector(".fv-rule-clean")).toBeInTheDocument();
  });
});

describe("RuleCard — skipped state", () => {
  const skipped = makeRule({
    rule_id: "K9",
    name: "Dangerous Post-Install Hooks",
    status: "skipped",
    findings: [],
    worstSeverity: null,
    skip_reason: {
      missing_inputs: ["source_code"],
      summary: "Source code not yet ingested for this server.",
    },
  });

  it("renders a 'Skipped' status pill and a dashed data-status rail", () => {
    const { container } = render(<RuleCard rule={skipped} />);
    expect(screen.getByText("Skipped")).toBeInTheDocument();
    const card = container.querySelector(".fv-rule");
    expect(card).toHaveAttribute("data-status", "skipped");
  });

  it("surfaces the skip reason and a labeled 'Needs · …' CTA per missing input", () => {
    const { container } = render(<RuleCard rule={skipped} />);
    expect(
      screen.getByText(/Source code not yet ingested/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/Needs · Source code/i)).toBeInTheDocument();
    expect(
      screen.getByText(/Add a GitHub URL to your server registration/i),
    ).toBeInTheDocument();
    expect(container.querySelector(".fv-rule-skipped")).toBeInTheDocument();
  });

  it("still renders the TESTS panel — tests visible for every status", () => {
    render(<RuleCard rule={skipped} />);
    expect(screen.getByText("Tests")).toBeInTheDocument();
    expect(screen.getByText("sanitizer-verified-by-name")).toBeInTheDocument();
  });
});
