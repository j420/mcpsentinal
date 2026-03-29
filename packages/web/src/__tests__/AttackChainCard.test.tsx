// @vitest-environment jsdom
/**
 * AttackChainCard Test Suite — packages/web/src/components/AttackChainCard.tsx
 *
 * Tests the main-branch AttackChainCard which:
 * - Takes { chains: AttackChainItem[] | null | undefined; currentServerId?: string }
 * - Is a list component with useState expand/collapse (one chain at a time)
 * - Returns null when !chains || chains.length === 0
 * - Uses ROLE_LABELS map (injection_gateway→"Entry Point", pivot→"Pivot", etc.)
 * - Uses RATING_LABELS map (critical→"Critical", high→"High", etc.)
 * - Shows 4 mitigations max with "+N more mitigations" overflow
 * - tools_involved shows 3 max with "+N" badge
 * - Mitigation effects: "BREAKS CHAIN" / "reduces risk"
 * - ac-step-highlight class for current server step
 * - aria-expanded on toggle button
 * - Chains collapsed by default; clicking expands body
 */
import { describe, it, expect } from "vitest";
import React from "react";
import { render, fireEvent } from "@testing-library/react";
import AttackChainCard, {
  type AttackChainItem,
  type AttackChainStep,
  type AttackChainMitigation,
} from "../components/AttackChainCard";

// ── Fixtures ────────────────────────────────────────────────────────────────

function makeStep(overrides: Partial<AttackChainStep> = {}): AttackChainStep {
  return {
    ordinal: 1,
    server_id: "srv-1",
    server_name: "web-scraper",
    role: "injection_gateway",
    capabilities_used: [],
    tools_involved: [],
    narrative: "Step 1 narrative",
    ...overrides,
  };
}

function makeMitigation(overrides: Partial<AttackChainMitigation> = {}): AttackChainMitigation {
  return {
    action: "remove_server",
    target_server_id: "srv-1",
    target_server_name: "web-scraper",
    description: "Remove the injection gateway",
    breaks_steps: [1, 2, 3],
    effect: "breaks_chain",
    ...overrides,
  };
}

function makeChain(overrides: Partial<AttackChainItem> = {}): AttackChainItem {
  return {
    id: "chain-001",
    chain_id: "cid-001",
    kill_chain_id: "KC01",
    kill_chain_name: "Indirect Injection → Data Exfiltration",
    steps: [
      makeStep({ ordinal: 1, server_id: "srv-1", server_name: "web-scraper", role: "injection_gateway" }),
      makeStep({ ordinal: 2, server_id: "srv-2", server_name: "file-manager", role: "data_source" }),
      makeStep({ ordinal: 3, server_id: "srv-3", server_name: "webhook-sender", role: "exfiltrator" }),
    ],
    exploitability_overall: 0.82,
    exploitability_rating: "critical",
    narrative: "An attacker can exploit this chain to steal data.",
    mitigations: [makeMitigation()],
    owasp_refs: ["MCP01", "MCP04"],
    mitre_refs: ["AML.T0054"],
    created_at: "2026-03-01T00:00:00Z",
    ...overrides,
  };
}

// ═════════════════════════════════════════════════════════════════════════════
// Null/undefined/empty handling
// ═════════════════════════════════════════════════════════════════════════════

describe("null/undefined/empty handling", () => {
  it("chains=null → renders nothing", () => {
    const { container } = render(<AttackChainCard chains={null} />);
    expect(container.innerHTML).toBe("");
  });

  it("chains=undefined → renders nothing", () => {
    const { container } = render(<AttackChainCard chains={undefined} />);
    expect(container.innerHTML).toBe("");
  });

  it("chains=[] → renders nothing", () => {
    const { container } = render(<AttackChainCard chains={[]} />);
    expect(container.innerHTML).toBe("");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Section header
// ═════════════════════════════════════════════════════════════════════════════

describe("section header", () => {
  it("renders section title 'Kill Chains Involving This Server'", () => {
    const { container } = render(<AttackChainCard chains={[makeChain()]} />);
    expect(container.textContent).toContain("Kill Chains Involving This Server");
  });

  it("renders chain count badge", () => {
    const chains = [makeChain({ id: "c1" }), makeChain({ id: "c2" })];
    const { container } = render(<AttackChainCard chains={chains} />);
    const countBadge = container.querySelector(".sd-section-count");
    expect(countBadge).not.toBeNull();
    expect(countBadge!.textContent).toBe("2");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Chain header rendering (collapsed state)
// ═════════════════════════════════════════════════════════════════════════════

describe("chain header rendering", () => {
  it("renders rating label 'Critical' for exploitability_rating='critical'", () => {
    const { container } = render(
      <AttackChainCard chains={[makeChain({ exploitability_rating: "critical" })]} />
    );
    expect(container.textContent).toContain("Critical");
  });

  it("renders rating label 'High' for exploitability_rating='high'", () => {
    const { container } = render(
      <AttackChainCard chains={[makeChain({ exploitability_rating: "high" })]} />
    );
    expect(container.textContent).toContain("High");
  });

  it("renders rating label 'Medium' for exploitability_rating='medium'", () => {
    const { container } = render(
      <AttackChainCard chains={[makeChain({ exploitability_rating: "medium" })]} />
    );
    expect(container.textContent).toContain("Medium");
  });

  it("renders rating label 'Low' for exploitability_rating='low'", () => {
    const { container } = render(
      <AttackChainCard chains={[makeChain({ exploitability_rating: "low" })]} />
    );
    expect(container.textContent).toContain("Low");
  });

  it("renders exploitability_overall as percentage: 0.82 → '82%'", () => {
    const { container } = render(
      <AttackChainCard chains={[makeChain({ exploitability_overall: 0.82 })]} />
    );
    expect(container.textContent).toContain("82%");
  });

  it("renders exploitability_overall 0.0 → '0%'", () => {
    const { container } = render(
      <AttackChainCard chains={[makeChain({ exploitability_overall: 0.0 })]} />
    );
    expect(container.textContent).toContain("0%");
  });

  it("renders exploitability_overall 1.0 → '100%'", () => {
    const { container } = render(
      <AttackChainCard chains={[makeChain({ exploitability_overall: 1.0 })]} />
    );
    expect(container.textContent).toContain("100%");
  });

  it("renders kill_chain_id and kill_chain_name in header", () => {
    const { container } = render(
      <AttackChainCard chains={[makeChain({ kill_chain_id: "KC07", kill_chain_name: "DB Privilege Escalation" })]} />
    );
    expect(container.textContent).toContain("KC07");
    expect(container.textContent).toContain("DB Privilege Escalation");
  });

  it("applies rating-specific CSS class on chain container", () => {
    const { container } = render(
      <AttackChainCard chains={[makeChain({ exploitability_rating: "high" })]} />
    );
    expect(container.querySelector(".ac-chain-high")).not.toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Current server role badge (collapsed header)
// ═════════════════════════════════════════════════════════════════════════════

describe("current server role badge", () => {
  it("shows role badge with ROLE_LABELS mapping when currentServerId matches a step", () => {
    const { container } = render(
      <AttackChainCard chains={[makeChain()]} currentServerId="srv-1" />
    );
    const badge = container.querySelector(".ac-server-role-badge");
    expect(badge).not.toBeNull();
    expect(badge!.textContent).toContain("Entry Point"); // injection_gateway → Entry Point
    expect(badge!.textContent).toContain("step 1");
    expect(badge!.textContent).toContain("of 3");
  });

  it("shows 'Pivot' for role='pivot'", () => {
    const chain = makeChain({
      steps: [makeStep({ server_id: "srv-x", role: "pivot" })],
    });
    const { container } = render(
      <AttackChainCard chains={[chain]} currentServerId="srv-x" />
    );
    expect(container.textContent).toContain("Pivot");
  });

  it("shows 'Data Source' for role='data_source'", () => {
    const chain = makeChain({
      steps: [makeStep({ server_id: "srv-x", role: "data_source" })],
    });
    const { container } = render(
      <AttackChainCard chains={[chain]} currentServerId="srv-x" />
    );
    expect(container.textContent).toContain("Data Source");
  });

  it("shows raw role string when role is unknown", () => {
    const chain = makeChain({
      steps: [makeStep({ server_id: "srv-x", role: "unknown_custom_role" })],
    });
    const { container } = render(
      <AttackChainCard chains={[chain]} currentServerId="srv-x" />
    );
    expect(container.textContent).toContain("unknown_custom_role");
  });

  it("no role badge when currentServerId does not match any step", () => {
    const { container } = render(
      <AttackChainCard chains={[makeChain()]} currentServerId="srv-nonexistent" />
    );
    expect(container.querySelector(".ac-server-role-badge")).toBeNull();
  });

  it("no role badge when currentServerId is undefined", () => {
    const { container } = render(
      <AttackChainCard chains={[makeChain()]} />
    );
    expect(container.querySelector(".ac-server-role-badge")).toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Expand/collapse behavior
// ═════════════════════════════════════════════════════════════════════════════

describe("expand/collapse behavior", () => {
  it("chains are collapsed by default (no chain body visible)", () => {
    const { container } = render(<AttackChainCard chains={[makeChain()]} />);
    expect(container.querySelector(".ac-server-chain-body")).toBeNull();
  });

  it("toggle button has aria-expanded=false by default", () => {
    const { container } = render(<AttackChainCard chains={[makeChain()]} />);
    const button = container.querySelector(".ac-server-chain-toggle");
    expect(button).not.toBeNull();
    expect(button!.getAttribute("aria-expanded")).toBe("false");
  });

  it("clicking toggle expands the chain body", () => {
    const { container } = render(<AttackChainCard chains={[makeChain()]} />);
    const button = container.querySelector(".ac-server-chain-toggle")!;
    fireEvent.click(button);
    expect(container.querySelector(".ac-server-chain-body")).not.toBeNull();
    expect(button.getAttribute("aria-expanded")).toBe("true");
  });

  it("clicking toggle twice collapses the chain body", () => {
    const { container } = render(<AttackChainCard chains={[makeChain()]} />);
    const button = container.querySelector(".ac-server-chain-toggle")!;
    fireEvent.click(button);
    expect(container.querySelector(".ac-server-chain-body")).not.toBeNull();
    fireEvent.click(button);
    expect(container.querySelector(".ac-server-chain-body")).toBeNull();
    expect(button.getAttribute("aria-expanded")).toBe("false");
  });

  it("only one chain expanded at a time — expanding second collapses first", () => {
    const chains = [makeChain({ id: "c1" }), makeChain({ id: "c2" })];
    const { container } = render(<AttackChainCard chains={chains} />);
    const buttons = container.querySelectorAll(".ac-server-chain-toggle");
    expect(buttons).toHaveLength(2);

    fireEvent.click(buttons[0]);
    expect(container.querySelectorAll(".ac-server-chain-body")).toHaveLength(1);

    fireEvent.click(buttons[1]);
    expect(container.querySelectorAll(".ac-server-chain-body")).toHaveLength(1);
    // Second chain expanded, first collapsed
    expect(buttons[0].getAttribute("aria-expanded")).toBe("false");
    expect(buttons[1].getAttribute("aria-expanded")).toBe("true");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Step flow rendering (expanded state)
// ═════════════════════════════════════════════════════════════════════════════

describe("step flow rendering", () => {
  function renderExpanded(chain: AttackChainItem, currentServerId?: string) {
    const { container } = render(
      <AttackChainCard chains={[chain]} currentServerId={currentServerId} />
    );
    const button = container.querySelector(".ac-server-chain-toggle")!;
    fireEvent.click(button);
    return container;
  }

  it("renders all 3 steps with server names and roles", () => {
    const container = renderExpanded(makeChain());
    expect(container.textContent).toContain("web-scraper");
    expect(container.textContent).toContain("file-manager");
    expect(container.textContent).toContain("webhook-sender");
  });

  it("renders ROLE_LABELS for known roles", () => {
    const container = renderExpanded(makeChain());
    expect(container.textContent).toContain("Entry Point");
    expect(container.textContent).toContain("Data Source");
    expect(container.textContent).toContain("Exfiltrator");
  });

  it("renders raw role string for unknown roles", () => {
    const chain = makeChain({
      steps: [makeStep({ role: "custom_unknown_role" })],
    });
    const container = renderExpanded(chain);
    expect(container.textContent).toContain("custom_unknown_role");
  });

  it("renders 2 arrow connectors between 3 steps", () => {
    const container = renderExpanded(makeChain());
    const arrows = container.querySelectorAll(".ac-step-arrow");
    expect(arrows).toHaveLength(2);
  });

  it("renders 0 arrow connectors for single step", () => {
    const chain = makeChain({
      steps: [makeStep()],
    });
    const container = renderExpanded(chain);
    const arrows = container.querySelectorAll(".ac-step-arrow");
    expect(arrows).toHaveLength(0);
  });

  it("highlights current server step with ac-step-highlight class", () => {
    const container = renderExpanded(makeChain(), "srv-2");
    const highlighted = container.querySelectorAll(".ac-step-highlight");
    expect(highlighted).toHaveLength(1);
    expect(highlighted[0].textContent).toContain("file-manager");
  });

  it("no highlight when currentServerId matches no step", () => {
    const container = renderExpanded(makeChain(), "srv-nonexistent");
    expect(container.querySelectorAll(".ac-step-highlight")).toHaveLength(0);
  });

  it("no highlight when currentServerId is undefined", () => {
    const container = renderExpanded(makeChain());
    expect(container.querySelectorAll(".ac-step-highlight")).toHaveLength(0);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Tools involved rendering (expanded state)
// ═════════════════════════════════════════════════════════════════════════════

describe("tools involved rendering", () => {
  function renderExpanded(chain: AttackChainItem) {
    const { container } = render(<AttackChainCard chains={[chain]} />);
    fireEvent.click(container.querySelector(".ac-server-chain-toggle")!);
    return container;
  }

  it("renders up to 3 tool badges", () => {
    const chain = makeChain({
      steps: [makeStep({ tools_involved: ["fetch_url", "read_file", "send_data"] })],
    });
    const container = renderExpanded(chain);
    expect(container.textContent).toContain("fetch_url");
    expect(container.textContent).toContain("read_file");
    expect(container.textContent).toContain("send_data");
  });

  it("shows +N overflow badge when >3 tools", () => {
    const chain = makeChain({
      steps: [makeStep({ tools_involved: ["t1", "t2", "t3", "t4", "t5"] })],
    });
    const container = renderExpanded(chain);
    expect(container.textContent).toContain("t1");
    expect(container.textContent).toContain("t2");
    expect(container.textContent).toContain("t3");
    expect(container.textContent).toContain("+2"); // 5-3 = 2
    // 4th and 5th tools should NOT appear as text
    expect(container.querySelectorAll(".ac-step-tool-more")).toHaveLength(1);
  });

  it("does not render tools section when tools_involved is empty", () => {
    const chain = makeChain({
      steps: [makeStep({ tools_involved: [] })],
    });
    const container = renderExpanded(chain);
    expect(container.querySelector(".ac-step-tools")).toBeNull();
  });

  it("does not render tools section when tools_involved is undefined", () => {
    const chain = makeChain({
      steps: [makeStep({ tools_involved: undefined })],
    });
    const container = renderExpanded(chain);
    expect(container.querySelector(".ac-step-tools")).toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Narrative rendering (expanded state)
// ═════════════════════════════════════════════════════════════════════════════

describe("narrative rendering", () => {
  it("renders chain narrative text when expanded", () => {
    const { container } = render(
      <AttackChainCard chains={[makeChain({ narrative: "This is a dangerous attack chain." })]} />
    );
    fireEvent.click(container.querySelector(".ac-server-chain-toggle")!);
    expect(container.textContent).toContain("This is a dangerous attack chain.");
  });

  it("handles very long narrative (1000 chars) without crash", () => {
    const longNarrative = "A".repeat(1000);
    const { container } = render(
      <AttackChainCard chains={[makeChain({ narrative: longNarrative })]} />
    );
    fireEvent.click(container.querySelector(".ac-server-chain-toggle")!);
    expect(container.textContent).toContain(longNarrative);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Mitigations rendering (expanded state)
// ═════════════════════════════════════════════════════════════════════════════

describe("mitigations rendering", () => {
  function renderExpanded(chain: AttackChainItem) {
    const { container } = render(<AttackChainCard chains={[chain]} />);
    fireEvent.click(container.querySelector(".ac-server-chain-toggle")!);
    return container;
  }

  it("renders 'BREAKS CHAIN' text for breaks_chain effect", () => {
    const chain = makeChain({
      mitigations: [makeMitigation({ effect: "breaks_chain" })],
    });
    const container = renderExpanded(chain);
    expect(container.textContent).toContain("BREAKS CHAIN");
  });

  it("renders 'reduces risk' text for reduces_risk effect", () => {
    const chain = makeChain({
      mitigations: [makeMitigation({ effect: "reduces_risk" })],
    });
    const container = renderExpanded(chain);
    expect(container.textContent).toContain("reduces risk");
  });

  it("renders mitigation description", () => {
    const chain = makeChain({
      mitigations: [makeMitigation({ description: "Remove the injection gateway" })],
    });
    const container = renderExpanded(chain);
    expect(container.textContent).toContain("Remove the injection gateway");
  });

  it("renders max 4 mitigations", () => {
    const mitigations = Array.from({ length: 6 }, (_, i) =>
      makeMitigation({ description: `Mit ${i}`, target_server_id: `s-${i}`, target_server_name: `server-${i}` })
    );
    const chain = makeChain({ mitigations });
    const container = renderExpanded(chain);
    // First 4 rendered
    expect(container.textContent).toContain("Mit 0");
    expect(container.textContent).toContain("Mit 1");
    expect(container.textContent).toContain("Mit 2");
    expect(container.textContent).toContain("Mit 3");
    // Overflow message
    expect(container.textContent).toContain("+2 more mitigations");
  });

  it("exactly 4 mitigations → no overflow message", () => {
    const mitigations = Array.from({ length: 4 }, (_, i) =>
      makeMitigation({ description: `Mit ${i}`, target_server_id: `s-${i}`, target_server_name: `s${i}` })
    );
    const chain = makeChain({ mitigations });
    const container = renderExpanded(chain);
    expect(container.textContent).not.toContain("more mitigations");
  });

  it("5 mitigations → '+1 more mitigations'", () => {
    const mitigations = Array.from({ length: 5 }, (_, i) =>
      makeMitigation({ description: `Mit ${i}`, target_server_id: `s-${i}`, target_server_name: `s${i}` })
    );
    const chain = makeChain({ mitigations });
    const container = renderExpanded(chain);
    expect(container.textContent).toContain("+1 more mitigations");
  });

  it("0 mitigations → no mitigations section", () => {
    const chain = makeChain({ mitigations: [] });
    const container = renderExpanded(chain);
    expect(container.querySelector(".ac-server-mitigations")).toBeNull();
  });

  it("applies 'ac-mit-breaks' class for breaks_chain effect", () => {
    const chain = makeChain({
      mitigations: [makeMitigation({ effect: "breaks_chain" })],
    });
    const container = renderExpanded(chain);
    expect(container.querySelector(".ac-mit-breaks")).not.toBeNull();
  });

  it("applies 'ac-mit-reduces' class for reduces_risk effect", () => {
    const chain = makeChain({
      mitigations: [makeMitigation({ effect: "reduces_risk" })],
    });
    const container = renderExpanded(chain);
    expect(container.querySelector(".ac-mit-reduces")).not.toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Framework tags rendering (expanded state)
// ═════════════════════════════════════════════════════════════════════════════

describe("framework tags rendering", () => {
  function renderExpanded(chain: AttackChainItem) {
    const { container } = render(<AttackChainCard chains={[chain]} />);
    fireEvent.click(container.querySelector(".ac-server-chain-toggle")!);
    return container;
  }

  it("renders OWASP ref tags", () => {
    const chain = makeChain({ owasp_refs: ["MCP01", "MCP04"] });
    const container = renderExpanded(chain);
    const owaspTags = container.querySelectorAll(".ac-tag-owasp");
    expect(owaspTags).toHaveLength(2);
    expect(owaspTags[0].textContent).toBe("MCP01");
    expect(owaspTags[1].textContent).toBe("MCP04");
  });

  it("renders MITRE ref tags", () => {
    const chain = makeChain({ mitre_refs: ["AML.T0054", "AML.T0057"] });
    const container = renderExpanded(chain);
    const mitreTags = container.querySelectorAll(".ac-tag-mitre");
    expect(mitreTags).toHaveLength(2);
    expect(mitreTags[0].textContent).toBe("AML.T0054");
    expect(mitreTags[1].textContent).toBe("AML.T0057");
  });

  it("renders no tags section when both refs are empty", () => {
    const chain = makeChain({ owasp_refs: [], mitre_refs: [] });
    const container = renderExpanded(chain);
    // Tags div still renders but should be empty
    const tags = container.querySelector(".ac-chain-tags");
    if (tags) {
      expect(tags.children).toHaveLength(0);
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Multiple chains
// ═════════════════════════════════════════════════════════════════════════════

describe("multiple chains", () => {
  it("renders all chains in the list", () => {
    const chains = [
      makeChain({ id: "c1", kill_chain_name: "Chain Alpha" }),
      makeChain({ id: "c2", kill_chain_name: "Chain Beta" }),
      makeChain({ id: "c3", kill_chain_name: "Chain Gamma" }),
    ];
    const { container } = render(<AttackChainCard chains={chains} />);
    expect(container.textContent).toContain("Chain Alpha");
    expect(container.textContent).toContain("Chain Beta");
    expect(container.textContent).toContain("Chain Gamma");
    expect(container.querySelector(".sd-section-count")!.textContent).toBe("3");
  });

  it("each chain has its own toggle button", () => {
    const chains = [makeChain({ id: "c1" }), makeChain({ id: "c2" })];
    const { container } = render(<AttackChainCard chains={chains} />);
    const buttons = container.querySelectorAll(".ac-server-chain-toggle");
    expect(buttons).toHaveLength(2);
  });

  it("mixed ratings render correct CSS classes", () => {
    const chains = [
      makeChain({ id: "c1", exploitability_rating: "critical" }),
      makeChain({ id: "c2", exploitability_rating: "low" }),
    ];
    const { container } = render(<AttackChainCard chains={chains} />);
    expect(container.querySelector(".ac-chain-critical")).not.toBeNull();
    expect(container.querySelector(".ac-chain-low")).not.toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Edge cases
// ═════════════════════════════════════════════════════════════════════════════

describe("edge cases", () => {
  it("chain with 0 steps → no step flow section when expanded", () => {
    const chain = makeChain({ steps: [] });
    const { container } = render(<AttackChainCard chains={[chain]} />);
    fireEvent.click(container.querySelector(".ac-server-chain-toggle")!);
    // The flow section should have no step children (but div may still exist)
    const steps = container.querySelectorAll(".ac-step");
    expect(steps).toHaveLength(0);
  });

  it("single chain with single step renders no arrows", () => {
    const chain = makeChain({
      steps: [makeStep({ ordinal: 1, server_id: "s1", server_name: "only-server", role: "executor" })],
    });
    const { container } = render(<AttackChainCard chains={[chain]} />);
    fireEvent.click(container.querySelector(".ac-server-chain-toggle")!);
    expect(container.querySelectorAll(".ac-step-arrow")).toHaveLength(0);
    expect(container.textContent).toContain("only-server");
    expect(container.textContent).toContain("Executor");
  });

  it("currentServerId matches multiple steps (same server appears twice)", () => {
    const chain = makeChain({
      steps: [
        makeStep({ ordinal: 1, server_id: "srv-x", server_name: "multi-role", role: "injection_gateway" }),
        makeStep({ ordinal: 2, server_id: "srv-x", server_name: "multi-role", role: "exfiltrator" }),
      ],
    });
    const { container } = render(
      <AttackChainCard chains={[chain]} currentServerId="srv-x" />
    );
    fireEvent.click(container.querySelector(".ac-server-chain-toggle")!);
    const highlighted = container.querySelectorAll(".ac-step-highlight");
    expect(highlighted).toHaveLength(2);
  });

  it("exploitability_overall displayed with .toFixed(0)", () => {
    // Component uses (chain.exploitability_overall * 100).toFixed(0)
    const chain = makeChain({ exploitability_overall: 0.756 });
    const { container } = render(<AttackChainCard chains={[chain]} />);
    // (0.756 * 100).toFixed(0) = "76"
    expect(container.textContent).toContain("76%");
  });

  it("exploitability_overall=0.999 → '100%' (rounding)", () => {
    const chain = makeChain({ exploitability_overall: 0.999 });
    const { container } = render(<AttackChainCard chains={[chain]} />);
    expect(container.textContent).toContain("100%");
  });

  it("chevron gets ac-chevron-open class when expanded", () => {
    const { container } = render(<AttackChainCard chains={[makeChain()]} />);
    const chevron = container.querySelector(".ac-chevron")!;
    expect(chevron.classList.contains("ac-chevron-open")).toBe(false);
    fireEvent.click(container.querySelector(".ac-server-chain-toggle")!);
    const openChevron = container.querySelector(".ac-chevron-open");
    expect(openChevron).not.toBeNull();
  });

  it("all 7 known roles render with their labels", () => {
    const roles = [
      ["injection_gateway", "Entry Point"],
      ["pivot", "Pivot"],
      ["data_source", "Data Source"],
      ["executor", "Executor"],
      ["exfiltrator", "Exfiltrator"],
      ["config_writer", "Config Writer"],
      ["memory_writer", "Memory Writer"],
    ] as const;
    for (const [role, label] of roles) {
      const chain = makeChain({
        steps: [makeStep({ server_id: "srv-x", role })],
      });
      const { container } = render(
        <AttackChainCard chains={[chain]} currentServerId="srv-x" />
      );
      expect(container.textContent).toContain(label);
    }
  });
});
