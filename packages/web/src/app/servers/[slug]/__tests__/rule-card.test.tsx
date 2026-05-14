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

describe("RuleCard (findings only)", () => {
  it("renders rule id, name, severity pill, and OWASP/MITRE chips", () => {
    render(<RuleCard rule={makeRule()} />);
    expect(screen.getByText("C1")).toBeInTheDocument();
    expect(screen.getByText("Command Injection")).toBeInTheDocument();
    expect(screen.getByText("MCP03")).toBeInTheDocument();
    expect(screen.getByText("AML.T0054")).toBeInTheDocument();
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("renders the severity rail keyed on worstSeverity and data-status=findings", () => {
    const { container } = render(<RuleCard rule={makeRule()} />);
    const card = container.querySelector(".fv-rule");
    expect(card).toHaveAttribute("data-severity", "critical");
    expect(card).toHaveAttribute("data-status", "findings");
  });

  it("renders the TESTS panel with humanized titles + raw ids + technique", () => {
    render(<RuleCard rule={makeRule()} />);
    expect(screen.getByText("Tests")).toBeInTheDocument();
    expect(screen.getByText("sanitizer-verified-by-name")).toBeInTheDocument();
    expect(screen.getByText("deep-pass-through")).toBeInTheDocument();
    expect(screen.getByText("Primary technique")).toBeInTheDocument();
    expect(screen.getByText("ast-taint")).toBeInTheDocument();
    expect(screen.getByText(/Sanitiser verification/i)).toBeInTheDocument();
  });

  it("renders the EVIDENCE panel with the prose fallback when chain is null", () => {
    render(<RuleCard rule={makeRule()} />);
    expect(screen.getByText("Evidence")).toBeInTheDocument();
    expect(screen.getByText("exec(req.query.cmd)")).toBeInTheDocument();
  });

  it("renders per-finding remediation 'Fix' aside", () => {
    render(<RuleCard rule={makeRule()} />);
    expect(screen.getByText("Fix")).toBeInTheDocument();
    expect(screen.getByText("Use execFile.")).toBeInTheDocument();
  });
});
