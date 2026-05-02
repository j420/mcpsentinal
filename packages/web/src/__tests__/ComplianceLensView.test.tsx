// @vitest-environment jsdom
/**
 * ComplianceLensView smoke tests — guards the rendering edges of the
 * Compliance lens. The transformer (compliance-shape.test.ts) covers
 * the data-shape correctness; this file covers what the user sees.
 */

import { afterEach, describe, expect, it } from "vitest";
import React from "react";
import { cleanup, render } from "@testing-library/react";
import ComplianceLensView from "@/components/ComplianceLensView";
import type { DeepDiveCategory, DeepDiveRule } from "@/lib/deep-dive";

afterEach(() => cleanup());

function rule(overrides: Partial<DeepDiveRule> & { rule_id: string }): DeepDiveRule {
  return {
    rule_id: overrides.rule_id,
    name: overrides.name ?? overrides.rule_id,
    severity: overrides.severity ?? "medium",
    category: overrides.category ?? "K",
    owasp: null,
    mitre: null,
    summary: "",
    framework_controls: overrides.framework_controls ?? [],
    methodology: {
      technique: "ast-taint",
      verified_edge_cases: [],
      edge_case_strategies: [],
      confidence_cap: null,
    },
    backing: null,
    remediation: "—",
    status: overrides.status ?? "passed",
    findings: overrides.findings ?? [],
  };
}

function emptySev() {
  return { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
}

function category(rules: DeepDiveRule[]): DeepDiveCategory {
  return {
    id: "x",
    title: "X",
    summary: "",
    frameworks: [],
    counts: {
      rules_total: rules.length,
      rules_passed: 0,
      rules_with_findings: 0,
      rules_skipped: 0,
      finding_count: 0,
      severity_breakdown: emptySev(),
    },
    sub_categories: [
      {
        id: "y",
        title: "Y",
        summary: "",
        counts: {
          rules_total: rules.length,
          rules_passed: 0,
          rules_with_findings: 0,
          rules_skipped: 0,
          finding_count: 0,
          severity_breakdown: emptySev(),
        },
        rules,
      },
    ],
  };
}

describe("ComplianceLensView", () => {
  it("renders the empty state when no rule carries framework_controls", () => {
    const cat = category([rule({ rule_id: "C1" })]);
    const { container } = render(
      <ComplianceLensView
        serverSlug="demo"
        categories={[cat]}
        apiOrigin="https://api.example.test"
      />,
    );
    expect(container.querySelector(".cl-empty")).toBeTruthy();
    expect(container.querySelector(".cl-fw-card")).toBeNull();
  });

  it("renders one card per framework with the friendly label", () => {
    const r = rule({
      rule_id: "K1",
      framework_controls: [
        { framework_id: "eu_ai_act", control_id: "Article 12", control_title: "Record-keeping" },
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "Prompt Injection" },
      ],
    });
    const { container, getByText } = render(
      <ComplianceLensView
        serverSlug="demo"
        categories={[category([r])]}
        apiOrigin="https://api.example.test"
      />,
    );
    const cards = container.querySelectorAll(".cl-fw-card");
    expect(cards.length).toBe(2);
    expect(getByText("EU AI Act")).toBeTruthy();
    expect(getByText("OWASP MCP Top 10")).toBeTruthy();
  });

  it("emits a Met / Unmet / Partial / N/A status pill per control with the right tone", () => {
    const passed = rule({
      rule_id: "K1",
      status: "passed",
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "x" },
      ],
    });
    const high = rule({
      rule_id: "K2",
      status: "findings",
      findings: [
        {
          id: "f",
          severity: "high",
          confidence: 1,
          evidence: "",
          evidence_chain: null,
          remediation: "",
        },
      ],
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP02", control_title: "x" },
      ],
    });
    const med = rule({
      rule_id: "K3",
      status: "findings",
      findings: [
        {
          id: "f",
          severity: "medium",
          confidence: 1,
          evidence: "",
          evidence_chain: null,
          remediation: "",
        },
      ],
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP03", control_title: "x" },
      ],
    });
    const skipped = rule({
      rule_id: "K4",
      status: "skipped",
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP04", control_title: "x" },
      ],
    });
    const { container } = render(
      <ComplianceLensView
        serverSlug="demo"
        categories={[category([passed, high, med, skipped])]}
        apiOrigin="https://api.example.test"
      />,
    );
    const tones = Array.from(container.querySelectorAll(".cl-control"))
      .map((el) => el.getAttribute("data-tone"))
      .sort();
    expect(tones).toEqual(["bad", "good", "muted", "warn"]);
  });

  it("emits HTML/PDF/JSON download links to the api signed-report endpoint", () => {
    const r = rule({
      rule_id: "K1",
      framework_controls: [
        { framework_id: "eu_ai_act", control_id: "Article 12", control_title: "x" },
      ],
    });
    const { container } = render(
      <ComplianceLensView
        serverSlug="demo-server"
        categories={[category([r])]}
        apiOrigin="https://api.example.test"
      />,
    );
    const links = Array.from(container.querySelectorAll(".cl-fw-action")).map(
      (a) => (a as HTMLAnchorElement).href,
    );
    expect(links).toContain(
      "https://api.example.test/api/v1/servers/demo-server/compliance/eu_ai_act.html",
    );
    expect(links).toContain(
      "https://api.example.test/api/v1/servers/demo-server/compliance/eu_ai_act.pdf",
    );
    expect(links).toContain(
      "https://api.example.test/api/v1/servers/demo-server/compliance/eu_ai_act.json",
    );
  });

  it("emits data-trace=`rule:` on every rule pill (wires into hover-trace)", () => {
    const r = rule({
      rule_id: "K1",
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "x" },
      ],
    });
    const { container } = render(
      <ComplianceLensView
        serverSlug="demo"
        categories={[category([r])]}
        apiOrigin="https://api.example.test"
      />,
    );
    expect(container.querySelector('[data-trace="rule:K1"]')).not.toBeNull();
  });

  it("emits data-trace=`control:` on every control row", () => {
    const r = rule({
      rule_id: "K1",
      framework_controls: [
        { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "x" },
      ],
    });
    const { container } = render(
      <ComplianceLensView
        serverSlug="demo"
        categories={[category([r])]}
        apiOrigin="https://api.example.test"
      />,
    );
    expect(
      container.querySelector('[data-trace="control:owasp_mcp:MCP01"]'),
    ).not.toBeNull();
  });

  it("encodes the server slug in the report URL (path-traversal guard)", () => {
    const r = rule({
      rule_id: "K1",
      framework_controls: [
        { framework_id: "eu_ai_act", control_id: "Article 12", control_title: "x" },
      ],
    });
    const { container } = render(
      <ComplianceLensView
        serverSlug="weird/slug with spaces"
        categories={[category([r])]}
        apiOrigin="https://api.example.test"
      />,
    );
    const link = container.querySelector(".cl-fw-action") as HTMLAnchorElement;
    expect(link.href).toContain(
      "/servers/weird%2Fslug%20with%20spaces/compliance/",
    );
  });
});
