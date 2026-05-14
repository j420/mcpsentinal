import React from "react";
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import RuleCard from "../rule-card";
import type { RuleWithFindings } from "../view-model";

afterEach(() => cleanup());

function makeRule(overrides: Partial<RuleWithFindings> = {}): RuleWithFindings {
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

describe("RuleCard", () => {
  it("renders rule id, name, severity pill, and OWASP/MITRE chips", () => {
    render(<RuleCard rule={makeRule()} />);
    expect(screen.getByText("C1")).toBeInTheDocument();
    expect(screen.getByText("Command Injection")).toBeInTheDocument();
    expect(screen.getByText("MCP03")).toBeInTheDocument();
    expect(screen.getByText("AML.T0054")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /Command Injection/i })).toBeInTheDocument();
  });

  it("renders the severity rail keyed on worstSeverity", () => {
    const { container } = render(<RuleCard rule={makeRule()} />);
    const card = container.querySelector(".fv-rule");
    expect(card).toHaveAttribute("data-severity", "critical");
  });

  it("renders EvidenceChainFlow per finding (falls back to prose when chain is null)", () => {
    render(<RuleCard rule={makeRule()} />);
    expect(screen.getByText("exec(req.query.cmd)")).toBeInTheDocument();
  });

  it("anchors the rule via id (#rule-c1)", () => {
    const { container } = render(<RuleCard rule={makeRule()} />);
    expect(container.querySelector("#rule-c1")).toBeInTheDocument();
  });

  it("shows MethodologyDrawer (collapsed by default)", () => {
    const { container } = render(<RuleCard rule={makeRule()} />);
    const details = container.querySelector("details.fv-method");
    expect(details).toBeInTheDocument();
    expect(details?.hasAttribute("open")).toBe(false);
  });

  it("renders per-finding count header when multiple findings exist", () => {
    const rule = makeRule({
      findings: [
        {
          id: "f1",
          severity: "high",
          confidence: 0.8,
          evidence: "first",
          evidence_chain: null,
          remediation: "fix",
        },
        {
          id: "f2",
          severity: "medium",
          confidence: 0.7,
          evidence: "second",
          evidence_chain: null,
          remediation: "fix",
        },
      ],
    });
    render(<RuleCard rule={rule} />);
    expect(screen.getByText(/Finding 1 of 2/i)).toBeInTheDocument();
    expect(screen.getByText(/Finding 2 of 2/i)).toBeInTheDocument();
  });

  it("renders the per-finding remediation 'Fix' aside", () => {
    render(<RuleCard rule={makeRule()} />);
    expect(screen.getByText("Fix")).toBeInTheDocument();
    expect(screen.getByText("Use execFile.")).toBeInTheDocument();
  });

  it("renders the TESTS panel inline with humanized titles + raw ids", () => {
    render(<RuleCard rule={makeRule()} />);
    expect(screen.getByText("Tests")).toBeInTheDocument();
    // Raw ids are surfaced as code chips
    expect(screen.getByText("sanitizer-verified-by-name")).toBeInTheDocument();
    expect(screen.getByText("deep-pass-through")).toBeInTheDocument();
    // Technique row shows the primary technique
    expect(screen.getByText("Primary technique")).toBeInTheDocument();
    expect(screen.getByText("ast-taint")).toBeInTheDocument();
    // Humanized titles surface in the test rows
    expect(screen.getByText(/Sanitiser verification/i)).toBeInTheDocument();
  });

  it("renders the section intros above TESTS and EVIDENCE", () => {
    render(<RuleCard rule={makeRule()} />);
    expect(screen.getByText(/How this rule decides/i)).toBeInTheDocument();
    expect(screen.getByText(/What we found/i)).toBeInTheDocument();
  });

  it("renders the EVIDENCE panel header with finding count", () => {
    const rule = makeRule({
      findings: [
        {
          id: "f1",
          severity: "high",
          confidence: 0.8,
          evidence: "first",
          evidence_chain: null,
          remediation: "fix",
        },
        {
          id: "f2",
          severity: "medium",
          confidence: 0.7,
          evidence: "second",
          evidence_chain: null,
          remediation: "fix",
        },
      ],
    });
    render(<RuleCard rule={rule} />);
    expect(screen.getByText("Evidence")).toBeInTheDocument();
    // Find the count next to the Evidence eyebrow specifically
    const evidenceHead = screen.getByText("Evidence").closest("header");
    expect(evidenceHead).not.toBeNull();
    expect(evidenceHead?.textContent).toMatch(/2 findings/);
  });

  it("shows an honest empty state when no edge_case_strategies declared", () => {
    const rule = makeRule({
      methodology: {
        technique: "",
        verified_edge_cases: [],
        edge_case_strategies: [],
        confidence_cap: null,
      },
    });
    render(<RuleCard rule={rule} />);
    expect(
      screen.getByText(/No edge-case strategies declared/i),
    ).toBeInTheDocument();
  });
});
