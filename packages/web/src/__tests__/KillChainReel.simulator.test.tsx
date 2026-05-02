// @vitest-environment jsdom
/**
 * KillChainReel — Mitigation Simulator behavioural tests.
 *
 * Guards:
 *   - Pills toggle on/off with click; aria-pressed reflects state
 *   - Toggling a mitigation that lists `breaks_steps: [1, 2]` greys
 *     out exactly steps 1 and 2 on its chain (not other chains)
 *   - Chain is marked "broken" when at least one applied mitigation has
 *     non-empty breaks_steps and effect != "reduces_risk"
 *   - "reduces_risk" mitigations grey steps but DON'T flip the broken pill
 *   - Status bar appears once at least one mitigation is applied; Reset
 *     clears all and the status bar disappears
 *   - Per-chain state is independent (toggle on chain A does not affect B)
 */

import { afterEach, describe, expect, it } from "vitest";
import React from "react";
import { cleanup, fireEvent, render } from "@testing-library/react";
import KillChainReel from "../components/KillChainReel";
import type { DeepDiveAttackChain } from "../lib/deep-dive";

afterEach(() => cleanup());

function chain(
  overrides: Partial<DeepDiveAttackChain> = {},
): DeepDiveAttackChain {
  return {
    chain_id: "chain-a",
    kill_chain_id: "KC01",
    kill_chain_name: "Indirect Injection → Data Exfiltration",
    steps: [
      { ordinal: 1, server_name: "web-scraper", role: "injection_gateway" },
      { ordinal: 2, server_name: "this-server", role: "data_source" },
      { ordinal: 3, server_name: "slack-mcp", role: "exfiltrator" },
    ],
    exploitability_overall: 0.78,
    exploitability_rating: "critical",
    narrative: "An attacker sends crafted content...",
    mitigations: [
      {
        action: "remove_server",
        target_server_name: "web-scraper",
        description: "Remove the injection entry point",
        breaks_steps: [1],
        effect: "breaks_chain",
      },
      {
        action: "disable_tool",
        target_server_name: "this-server",
        description: "Disable read_file on this server",
        breaks_steps: [2],
        effect: "breaks_chain",
      },
      {
        action: "rate_limit",
        target_server_name: "slack-mcp",
        description: "Rate-limit slack send",
        breaks_steps: [3],
        effect: "reduces_risk",
      },
    ],
    owasp_refs: ["MCP01"],
    mitre_refs: ["AML.T0054"],
    ...overrides,
  };
}

describe("KillChainReel — Mitigation Simulator", () => {
  it("renders a button per mitigation with aria-pressed=false initially", () => {
    const { container, getAllByRole } = render(
      <KillChainReel chains={[chain()]} />,
    );
    const buttons = getAllByRole("button");
    // Three mitigation pills + no Reset button yet (no mitigations applied).
    expect(buttons.length).toBe(3);
    for (const b of buttons) {
      expect(b.getAttribute("aria-pressed")).toBe("false");
    }
    expect(container.querySelector(".kcr-sim-bar")).toBeNull();
  });

  it("clicking a mitigation toggles aria-pressed and adds the applied class", () => {
    const { container } = render(<KillChainReel chains={[chain()]} />);
    const pills = container.querySelectorAll(".kcr-mit-sim-pill");
    expect(pills.length).toBe(3);
    fireEvent.click(pills[0]!);
    expect(pills[0]!.getAttribute("aria-pressed")).toBe("true");
    expect(pills[0]!.classList.contains("kcr-mit-sim-pill-applied")).toBe(true);
    // Other pills unaffected.
    expect(pills[1]!.getAttribute("aria-pressed")).toBe("false");
    // Toggle off.
    fireEvent.click(pills[0]!);
    expect(pills[0]!.getAttribute("aria-pressed")).toBe("false");
  });

  it("greys exactly the steps listed in breaks_steps[] of an applied mitigation", () => {
    const { container } = render(<KillChainReel chains={[chain()]} />);
    const pills = container.querySelectorAll(".kcr-mit-sim-pill");
    fireEvent.click(pills[0]!); // breaks step 1

    const steps = container.querySelectorAll(".kcr-step");
    expect(steps[0]!.getAttribute("data-broken")).toBe("true");
    expect(steps[1]!.getAttribute("data-broken")).toBeNull();
    expect(steps[2]!.getAttribute("data-broken")).toBeNull();

    // Apply the second mitigation (breaks step 2) — both should be greyed.
    fireEvent.click(pills[1]!);
    const stepsAgain = container.querySelectorAll(".kcr-step");
    expect(stepsAgain[0]!.getAttribute("data-broken")).toBe("true");
    expect(stepsAgain[1]!.getAttribute("data-broken")).toBe("true");
    expect(stepsAgain[2]!.getAttribute("data-broken")).toBeNull();
  });

  it("flips the chain-broken badge ONLY for breaks_chain (not reduces_risk)", () => {
    const { container } = render(<KillChainReel chains={[chain()]} />);
    const pills = container.querySelectorAll(".kcr-mit-sim-pill");

    // The third pill is "reduces_risk" — applying it should NOT flip the
    // broken badge, even though it greys step 3.
    fireEvent.click(pills[2]!);
    expect(
      container.querySelector(".kcr-card")!.getAttribute("data-chain-broken"),
    ).toBeNull();
    expect(container.querySelector(".kcr-card-broken")).toBeNull();
    // Step 3 is still greyed (visual signal) — only the chain isn't.
    const steps = container.querySelectorAll(".kcr-step");
    expect(steps[2]!.getAttribute("data-broken")).toBe("true");

    // Now apply pill 0 (breaks_chain) — chain flips to broken.
    fireEvent.click(pills[0]!);
    expect(
      container.querySelector(".kcr-card")!.getAttribute("data-chain-broken"),
    ).toBe("true");
    expect(container.querySelector(".kcr-card-broken")).not.toBeNull();
  });

  it("status bar appears with applied count + broken count once any mitigation is applied", () => {
    const { container } = render(<KillChainReel chains={[chain()]} />);
    expect(container.querySelector(".kcr-sim-bar")).toBeNull();
    fireEvent.click(container.querySelectorAll(".kcr-mit-sim-pill")[0]!);
    const bar = container.querySelector(".kcr-sim-bar");
    expect(bar).not.toBeNull();
    expect(bar!.textContent).toContain("1 of 1 chain");
    expect(bar!.textContent).toContain("1 mitigation");
  });

  it("Reset clears state, hides status bar, restores all steps", () => {
    const { container } = render(<KillChainReel chains={[chain()]} />);
    const pills = container.querySelectorAll(".kcr-mit-sim-pill");
    fireEvent.click(pills[0]!);
    fireEvent.click(pills[1]!);
    fireEvent.click(container.querySelector(".kcr-sim-bar-reset")!);
    expect(container.querySelector(".kcr-sim-bar")).toBeNull();
    const stepsAfter = container.querySelectorAll(".kcr-step");
    for (const s of stepsAfter) {
      expect(s.getAttribute("data-broken")).toBeNull();
    }
    const pillsAfter = container.querySelectorAll(".kcr-mit-sim-pill");
    for (const p of pillsAfter) {
      expect(p.getAttribute("aria-pressed")).toBe("false");
    }
  });

  it("per-chain simulator state is independent (toggling A does not affect B)", () => {
    const a = chain({ chain_id: "chain-a" });
    const b = chain({
      chain_id: "chain-b",
      kill_chain_id: "KC02",
      kill_chain_name: "Credential Harvesting Chain",
    });
    const { container } = render(<KillChainReel chains={[a, b]} />);
    const cards = container.querySelectorAll(".kcr-card");
    expect(cards.length).toBe(2);
    const aPills = cards[0]!.querySelectorAll(".kcr-mit-sim-pill");
    const bPills = cards[1]!.querySelectorAll(".kcr-mit-sim-pill");

    fireEvent.click(aPills[0]!);
    // A is broken, B is not.
    expect(cards[0]!.getAttribute("data-chain-broken")).toBe("true");
    expect(cards[1]!.getAttribute("data-chain-broken")).toBeNull();
    // Status bar reports 1 of 2 broken.
    expect(container.querySelector(".kcr-sim-bar")!.textContent).toContain(
      "1 of 2 chain",
    );

    // Apply on B too — both broken.
    fireEvent.click(bPills[0]!);
    expect(cards[0]!.getAttribute("data-chain-broken")).toBe("true");
    expect(cards[1]!.getAttribute("data-chain-broken")).toBe("true");
    expect(container.querySelector(".kcr-sim-bar")!.textContent).toContain(
      "2 of 2 chain",
    );
  });

  it("status bar carries data-sim-state=all-broken when every chain is broken", () => {
    const { container } = render(<KillChainReel chains={[chain()]} />);
    fireEvent.click(container.querySelectorAll(".kcr-mit-sim-pill")[0]!);
    expect(
      container.querySelector(".kcr-sim-bar")!.getAttribute("data-sim-state"),
    ).toBe("all-broken");
  });

  it("survives a partial chain shape (no mitigations array) without throwing", () => {
    const partial = {
      chain_id: "x",
      kill_chain_id: "KC01",
      kill_chain_name: "x",
      steps: [],
      exploitability_overall: 0.5,
      exploitability_rating: "high",
      narrative: "",
      // mitigations OMITTED
      owasp_refs: [],
      mitre_refs: [],
    } as unknown as DeepDiveAttackChain;
    expect(() => render(<KillChainReel chains={[partial]} />)).not.toThrow();
  });
});
