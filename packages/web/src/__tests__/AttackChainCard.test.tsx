// @vitest-environment jsdom
/**
 * AttackChainCard Test Suite — packages/web/src/components/AttackChainCard.tsx
 *
 * Tests rendering correctness, null-safety, current-server highlighting,
 * step flow arrows, mitigations, framework tags, narrative, and evidence
 * integration with EvidenceChainViz.
 *
 * Uses Vitest + React Testing Library (jsdom environment).
 */
import { describe, it, expect } from "vitest";
import React from "react";
import { render } from "@testing-library/react";
import {
  AttackChainCard,
  type AttackChainData,
  type AttackStep,
  type Mitigation,
} from "../components/AttackChainCard";

// ── Fixtures ────────────────────────────────────────────────────────────────

function makeChainData(overrides: Partial<AttackChainData> = {}): AttackChainData {
  return {
    chain_id: "abcdef1234567890",
    kill_chain_id: "KC01",
    kill_chain_name: "Indirect Injection \u2192 Data Exfiltration",
    steps: [
      { ordinal: 1, server_id: "srv-1", server_name: "web-scraper", role: "injection_gateway", capabilities_used: [], tools_involved: [], narrative: "Step 1" },
      { ordinal: 2, server_id: "srv-2", server_name: "file-manager", role: "data_source", capabilities_used: [], tools_involved: [], narrative: "Step 2" },
      { ordinal: 3, server_id: "srv-3", server_name: "webhook-sender", role: "exfiltrator", capabilities_used: [], tools_involved: [], narrative: "Step 3" },
    ],
    exploitability_overall: 0.82,
    exploitability_rating: "critical",
    narrative: "An attacker can exploit this chain to steal data.",
    mitigations: [
      { action: "remove_server", target_server_name: "web-scraper", description: "Remove the injection gateway", breaks_steps: [1, 2, 3], effect: "breaks_chain" as const },
    ],
    owasp_refs: ["MCP01", "MCP04"],
    mitre_refs: ["AML.T0054"],
    ...overrides,
  };
}

// ═════════════════════════════════════════════════════════════════════════════
// Null/undefined/empty handling
// ═════════════════════════════════════════════════════════════════════════════

describe("Null/undefined/empty handling", () => {
  it("renders without crash when steps is null", () => {
    const chain = makeChainData({ steps: null as unknown as AttackStep[] });
    const { container } = render(<AttackChainCard chain={chain} />);
    // Should render the card without throwing
    expect(container.querySelector(".attack-chain-card")).toBeTruthy();
    // Should NOT render the "Attack Steps" section
    expect(container.textContent).not.toContain("Attack Steps");
  });

  it("renders without crash when mitigations is null", () => {
    const chain = makeChainData({ mitigations: null as unknown as Mitigation[] });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.querySelector(".attack-chain-card")).toBeTruthy();
    // Should NOT render the "Mitigations" section
    expect(container.textContent).not.toContain("Mitigations");
  });

  it("does not render 'Attack Steps' section when steps is empty array", () => {
    const chain = makeChainData({ steps: [] });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).not.toContain("Attack Steps");
  });

  it("does not render 'Mitigations' section when mitigations is empty array", () => {
    const chain = makeChainData({ mitigations: [] });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).not.toContain("Mitigations");
  });

  it("does not render framework refs section when owasp_refs and mitre_refs are both empty", () => {
    const chain = makeChainData({ owasp_refs: [], mitre_refs: [] });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).not.toContain("OWASP:");
    expect(container.textContent).not.toContain("MITRE:");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Chain header rendering
// ═════════════════════════════════════════════════════════════════════════════

describe("Chain header rendering", () => {
  it("renders rating 'critical' as uppercase badge text", () => {
    const chain = makeChainData({ exploitability_rating: "critical" });
    const { container } = render(<AttackChainCard chain={chain} />);
    // The badge span should contain "critical" and have textTransform uppercase
    const spans = container.querySelectorAll("span");
    const badge = Array.from(spans).find(
      (s) => s.textContent === "critical" && s.style.textTransform === "uppercase"
    );
    expect(badge).toBeTruthy();
  });

  it("renders rating 'high' badge text", () => {
    const chain = makeChainData({ exploitability_rating: "high" });
    const { container } = render(<AttackChainCard chain={chain} />);
    const spans = container.querySelectorAll("span");
    const badge = Array.from(spans).find(
      (s) => s.textContent === "high" && s.style.textTransform === "uppercase"
    );
    expect(badge).toBeTruthy();
  });

  it("renders rating 'medium' badge text", () => {
    const chain = makeChainData({ exploitability_rating: "medium" });
    const { container } = render(<AttackChainCard chain={chain} />);
    const spans = container.querySelectorAll("span");
    const badge = Array.from(spans).find(
      (s) => s.textContent === "medium" && s.style.textTransform === "uppercase"
    );
    expect(badge).toBeTruthy();
  });

  it("renders rating 'low' badge text", () => {
    const chain = makeChainData({ exploitability_rating: "low" });
    const { container } = render(<AttackChainCard chain={chain} />);
    const spans = container.querySelectorAll("span");
    const badge = Array.from(spans).find(
      (s) => s.textContent === "low" && s.style.textTransform === "uppercase"
    );
    expect(badge).toBeTruthy();
  });

  it("renders unknown rating with fallback gray color (#6b7280)", () => {
    const chain = makeChainData({ exploitability_rating: "unknown_rating" });
    const { container } = render(<AttackChainCard chain={chain} />);
    const spans = container.querySelectorAll("span");
    const badge = Array.from(spans).find(
      (s) => s.textContent === "unknown_rating" && s.style.textTransform === "uppercase"
    );
    expect(badge).toBeTruthy();
    // jsdom normalizes hex to rgb
    expect(badge!.style.color).toBe("rgb(107, 114, 128)");
  });

  it("displays exploitability_overall 0.75 as '75%'", () => {
    const chain = makeChainData({ exploitability_overall: 0.75 });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).toContain("75%");
  });

  it("displays exploitability_overall 0.0 as '0%'", () => {
    const chain = makeChainData({ exploitability_overall: 0.0 });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).toContain("Exploitability: 0%");
  });

  it("displays exploitability_overall 1.0 as '100%'", () => {
    const chain = makeChainData({ exploitability_overall: 1.0 });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).toContain("100%");
  });

  it("clamps exploitability_overall 1.5 to '100%'", () => {
    const chain = makeChainData({ exploitability_overall: 1.5 });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).toContain("Exploitability: 100%");
  });

  it("clamps exploitability_overall -0.3 to '0%'", () => {
    const chain = makeChainData({ exploitability_overall: -0.3 });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).toContain("Exploitability: 0%");
  });

  it("displays kill_chain_name in header", () => {
    const chain = makeChainData({ kill_chain_name: "Custom Kill Chain Name" });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).toContain("Custom Kill Chain Name");
  });

  it("displays first 8 characters of chain_id", () => {
    const chain = makeChainData({ chain_id: "abcdef1234567890" });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).toContain("abcdef12");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Current server highlighting
// ═════════════════════════════════════════════════════════════════════════════

describe("Current server highlighting", () => {
  it("highlights step when currentServerId matches step.server_id", () => {
    const chain = makeChainData();
    const { container } = render(<AttackChainCard chain={chain} currentServerId="srv-2" />);
    // Find all step divs (inline-flex with server names)
    const stepDivs = container.querySelectorAll("div[style]");
    // jsdom normalizes hex to rgb in border, so match on rgb
    const highlightedStep = Array.from(stepDivs).find(
      (d) =>
        (d as HTMLElement).style.border === "2px solid rgb(59, 130, 246)" &&
        d.textContent?.includes("file-manager")
    );
    expect(highlightedStep).toBeTruthy();
    // Check fontWeight 700 on the server name span inside highlighted step
    const nameSpan = highlightedStep!.querySelectorAll("span")[1]; // second span is server_name
    expect(nameSpan.style.fontWeight).toBe("700");
  });

  it("no step highlighted when currentServerId matches no steps", () => {
    const chain = makeChainData();
    const { container } = render(<AttackChainCard chain={chain} currentServerId="srv-nonexistent" />);
    const stepDivs = container.querySelectorAll("div[style]");
    const highlighted = Array.from(stepDivs).filter(
      (d) => (d as HTMLElement).style.border === "2px solid rgb(59, 130, 246)"
    );
    expect(highlighted.length).toBe(0);
  });

  it("no step highlighted when currentServerId is undefined", () => {
    const chain = makeChainData();
    const { container } = render(<AttackChainCard chain={chain} />);
    const stepDivs = container.querySelectorAll("div[style]");
    const highlighted = Array.from(stepDivs).filter(
      (d) => (d as HTMLElement).style.border === "2px solid rgb(59, 130, 246)"
    );
    expect(highlighted.length).toBe(0);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Step flow rendering
// ═════════════════════════════════════════════════════════════════════════════

describe("Step flow rendering", () => {
  it("renders 2 steps with 1 arrow between them", () => {
    const chain = makeChainData({
      steps: [
        { ordinal: 1, server_id: "s1", server_name: "server-a", role: "source", capabilities_used: [], tools_involved: [], narrative: "" },
        { ordinal: 2, server_id: "s2", server_name: "server-b", role: "sink", capabilities_used: [], tools_involved: [], narrative: "" },
      ],
    });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).toContain("server-a");
    expect(container.textContent).toContain("server-b");
    // Count arrow spans: "\u2192"
    const arrows = container.querySelectorAll("span");
    const arrowSpans = Array.from(arrows).filter((s) => s.textContent === "\u2192");
    expect(arrowSpans.length).toBe(1);
  });

  it("renders 3 steps with 2 arrows between them", () => {
    const chain = makeChainData(); // default has 3 steps
    const { container } = render(<AttackChainCard chain={chain} />);
    const arrows = container.querySelectorAll("span");
    const arrowSpans = Array.from(arrows).filter((s) => s.textContent === "\u2192");
    expect(arrowSpans.length).toBe(2);
  });

  it("shows step ordinal, server_name, and role with underscores replaced by spaces", () => {
    const chain = makeChainData({
      steps: [
        { ordinal: 1, server_id: "s1", server_name: "my-server", role: "injection_gateway", capabilities_used: [], tools_involved: [], narrative: "" },
      ],
    });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).toContain("1.");
    expect(container.textContent).toContain("my-server");
    expect(container.textContent).toContain("injection gateway");
    // Should NOT contain the underscored version
    expect(container.textContent).not.toContain("injection_gateway");
  });

  it("replaces underscores with spaces in role display", () => {
    const chain = makeChainData({
      steps: [
        { ordinal: 1, server_id: "s1", server_name: "srv", role: "data_source", capabilities_used: [], tools_involved: [], narrative: "" },
      ],
    });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).toContain("(data source)");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Mitigations rendering
// ═════════════════════════════════════════════════════════════════════════════

describe("Mitigations rendering", () => {
  it("renders all 3 mitigations when provided", () => {
    const chain = makeChainData({
      mitigations: [
        { action: "remove_server", target_server_name: "srv-a", description: "Remove A", breaks_steps: [1], effect: "breaks_chain" },
        { action: "add_filter", target_server_name: "srv-b", description: "Add filter to B", breaks_steps: [2], effect: "reduces_risk" },
        { action: "sandbox", target_server_name: "srv-c", description: "Sandbox C", breaks_steps: [3], effect: "breaks_chain" },
      ],
    });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).toContain("srv-a:");
    expect(container.textContent).toContain("srv-b:");
    expect(container.textContent).toContain("srv-c:");
  });

  it("renders 'BREAKS' text with green color for breaks_chain effect", () => {
    const chain = makeChainData({
      mitigations: [
        { action: "remove_server", target_server_name: "srv-a", description: "Remove it", breaks_steps: [1], effect: "breaks_chain" },
      ],
    });
    const { container } = render(<AttackChainCard chain={chain} />);
    const spans = container.querySelectorAll("span");
    const breaksSpan = Array.from(spans).find((s) => s.textContent === "BREAKS");
    expect(breaksSpan).toBeTruthy();
    expect(breaksSpan!.style.color).toBe("rgb(5, 150, 105)");
  });

  it("renders 'REDUCES' text with amber color for reduces_risk effect", () => {
    const chain = makeChainData({
      mitigations: [
        { action: "add_filter", target_server_name: "srv-b", description: "Filter input", breaks_steps: [2], effect: "reduces_risk" },
      ],
    });
    const { container } = render(<AttackChainCard chain={chain} />);
    const spans = container.querySelectorAll("span");
    const reducesSpan = Array.from(spans).find((s) => s.textContent === "REDUCES");
    expect(reducesSpan).toBeTruthy();
    expect(reducesSpan!.style.color).toBe("rgb(245, 158, 11)");
  });

  it("shows target_server_name in bold and description", () => {
    const chain = makeChainData({
      mitigations: [
        { action: "remove_server", target_server_name: "critical-server", description: "Shut it down", breaks_steps: [1], effect: "breaks_chain" },
      ],
    });
    const { container } = render(<AttackChainCard chain={chain} />);
    const bold = container.querySelector("strong");
    expect(bold).toBeTruthy();
    expect(bold!.textContent).toContain("critical-server");
    expect(container.textContent).toContain("Shut it down");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Framework tags
// ═════════════════════════════════════════════════════════════════════════════

describe("Framework tags", () => {
  it("renders OWASP refs as comma-separated list", () => {
    const chain = makeChainData({ owasp_refs: ["MCP01", "MCP04"] });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).toContain("OWASP:");
    expect(container.textContent).toContain("MCP01, MCP04");
  });

  it("renders MITRE refs", () => {
    const chain = makeChainData({ mitre_refs: ["AML.T0057"] });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).toContain("MITRE:");
    expect(container.textContent).toContain("AML.T0057");
  });

  it("does not render framework section when both refs are empty", () => {
    const chain = makeChainData({ owasp_refs: [], mitre_refs: [] });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).not.toContain("OWASP:");
    expect(container.textContent).not.toContain("MITRE:");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Narrative
// ═════════════════════════════════════════════════════════════════════════════

describe("Narrative", () => {
  it("renders the chain narrative text", () => {
    const chain = makeChainData({ narrative: "This is a dangerous attack chain." });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).toContain("This is a dangerous attack chain.");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Evidence
// ═════════════════════════════════════════════════════════════════════════════

describe("Evidence", () => {
  it("renders EvidenceChainViz when chain.evidence is present", () => {
    const chain = makeChainData({
      evidence: {
        links: [
          { type: "source", location: "handler.ts:10", observed: "user input" },
        ],
        confidence: 0.9,
      },
    });
    const { container } = render(<AttackChainCard chain={chain} />);
    // EvidenceChainViz renders with class "evidence-chain-viz"
    const evidenceViz = container.querySelector(".evidence-chain-viz");
    expect(evidenceViz).toBeTruthy();
  });

  it("does not render EvidenceChainViz when chain.evidence is undefined", () => {
    const chain = makeChainData({ evidence: undefined });
    const { container } = render(<AttackChainCard chain={chain} />);
    const evidenceViz = container.querySelector(".evidence-chain-viz");
    expect(evidenceViz).toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Edge cases
// ═════════════════════════════════════════════════════════════════════════════

describe("Edge cases", () => {
  it("handles very long narrative (1000 chars) without crash", () => {
    const longNarrative = "A".repeat(1000);
    const chain = makeChainData({ narrative: longNarrative });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).toContain(longNarrative);
  });

  it("replaces special characters in role underscores with spaces", () => {
    const chain = makeChainData({
      steps: [
        { ordinal: 1, server_id: "s1", server_name: "srv", role: "multi_word_role_name", capabilities_used: [], tools_involved: [], narrative: "" },
      ],
    });
    const { container } = render(<AttackChainCard chain={chain} />);
    expect(container.textContent).toContain("(multi word role name)");
    expect(container.textContent).not.toContain("multi_word_role_name");
  });
});
