// @vitest-environment jsdom
/**
 * RiskBoundaryTab Test Suite
 *
 * The component is an async Server Component that consumes the frozen contract
 * `GET /api/v1/servers/:slug/risk-boundary`. Tests stub `fetch` directly,
 * mirroring the FrameworkPostureMatrix test pattern.
 *
 * Coverage required by Cluster C briefing (8 cases minimum):
 *   1. happy path with patterns + chains → all P0X + KC0X rendered with
 *      severity tints, names verbatim from API
 *   2. empty arrays both → "no cross-config exposure on file" panel renders,
 *      not hidden
 *   3. API 404 → "data unavailable" panel
 *   4. sample_pairings capped at 5 — when API ships 5, all 5 link to
 *      /servers/<slug>; when 0, no list rendered
 *   5. severity tints map correctly (critical/high/medium/low →
 *      critical/poor/moderate/text-2 — via class name suffix)
 *   6. contributing_rule_ids render as visible badges
 *   7. cve_evidence_ids and mitigations render as separate sections per chain
 *   8. accessibility: severity gauge carries role="img" + aria-label
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import React from "react";
import { render } from "@testing-library/react";
import RiskBoundaryTab, {
  type RiskBoundaryData,
  type RiskBoundaryPattern,
  type RiskBoundaryKillChain,
} from "../components/RiskBoundaryTab";

const API_URL = "https://api.mcp-sentinel.test";
const SLUG = "demo-server";

// ── Helpers ────────────────────────────────────────────────────────────────

function makePattern(overrides: Partial<RiskBoundaryPattern> = {}): RiskBoundaryPattern {
  return {
    pattern_id: "P01",
    pattern_name: "Lethal Trifecta Co-Occurrence",
    pattern_summary: "Private data + untrusted content + external comms in adjacent servers.",
    severity: "critical",
    paired_with_count: 4,
    sample_pairings: [
      { slug: "server-a", name: "Server A" },
      { slug: "server-b", name: "Server B" },
    ],
    ...overrides,
  };
}

function makeChain(overrides: Partial<RiskBoundaryKillChain> = {}): RiskBoundaryKillChain {
  return {
    kc_id: "KC01",
    name: "Indirect Injection → Exfiltration",
    severity_score: 75,
    narrative:
      "Attacker injects via web-scraping tool, AI propagates payload to a sender tool.",
    contributing_rule_ids: ["A1", "F1", "G1"],
    cve_evidence_ids: ["CVE-2025-6514"],
    mitigations: ["Disable autonomous tool chaining for unverified content."],
    ...overrides,
  };
}

function makePayload(
  patterns: RiskBoundaryPattern[],
  chains: RiskBoundaryKillChain[],
): RiskBoundaryData {
  return {
    server_slug: SLUG,
    server_name: "Demo Server",
    same_config_patterns: patterns,
    kill_chains: chains,
  };
}

function mockFetchWith(payload: RiskBoundaryData, status = 200): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({
      ok: status >= 200 && status < 300,
      status,
      json: async () => ({ data: payload }),
    } as Response)),
  );
}

function mockFetchStatus(status: number): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({
      ok: status >= 200 && status < 300,
      status,
      json: async () => ({ error: "not found" }),
    } as Response)),
  );
}

function mockFetchThrows(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => { throw new Error("network broken"); }),
  );
}

async function renderComponent() {
  const node = await RiskBoundaryTab({ slug: SLUG, apiUrl: API_URL });
  return render(node);
}

beforeEach(() => {});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

// ═══════════════════════════════════════════════════════════════════════════
// 1. Happy path — patterns + chains both populated
// ═══════════════════════════════════════════════════════════════════════════

describe("happy path with patterns + chains", () => {
  it("renders every P0X pattern and every KC0X chain verbatim from the API", async () => {
    const patterns = [
      makePattern({
        pattern_id: "P01",
        pattern_name: "Lethal Trifecta Co-Occurrence",
        pattern_summary: "Three servers create the lethal trifecta together.",
        severity: "critical",
      }),
      makePattern({
        pattern_id: "P05",
        pattern_name: "Filesystem + Network Pivot",
        pattern_summary: "Filesystem reader paired with network sender.",
        severity: "high",
      }),
      makePattern({
        pattern_id: "P12",
        pattern_name: "Memory-Sharing Servers",
        pattern_summary: "Two servers writing to the same vector store.",
        severity: "medium",
      }),
    ];
    const chains = [
      makeChain({
        kc_id: "KC02",
        name: "Filesystem Pivot Chain",
        severity_score: 88,
      }),
      makeChain({
        kc_id: "KC07",
        name: "Memory Poisoning Cascade",
        severity_score: 42,
      }),
    ];
    mockFetchWith(makePayload(patterns, chains));
    const { container } = await renderComponent();

    // Every pattern renders
    const patternEls = container.querySelectorAll(".rbt-pattern");
    expect(patternEls).toHaveLength(3);
    const patternIds = Array.from(patternEls).map((p) =>
      p.getAttribute("data-pattern-id"),
    );
    expect(patternIds).toEqual(["P01", "P05", "P12"]);

    // Names render verbatim — no client-side relabelling
    expect(container.textContent).toContain("Lethal Trifecta Co-Occurrence");
    expect(container.textContent).toContain("Filesystem + Network Pivot");
    expect(container.textContent).toContain("Memory-Sharing Servers");

    // Every chain renders
    const chainEls = container.querySelectorAll(".rbt-chain");
    expect(chainEls).toHaveLength(2);
    const kcIds = Array.from(chainEls).map((c) => c.getAttribute("data-kc-id"));
    expect(kcIds).toEqual(["KC02", "KC07"]);

    expect(container.textContent).toContain("Filesystem Pivot Chain");
    expect(container.textContent).toContain("Memory Poisoning Cascade");

    // The state attribute confirms we took the data path
    expect(container.querySelector("[data-rbt-state=\"ok\"]")).not.toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. Empty arrays both → explicit "no cross-config exposure" panel
// ═══════════════════════════════════════════════════════════════════════════

describe("empty arrays both", () => {
  it("renders the 'no cross-config exposure on file' panel — not hidden", async () => {
    mockFetchWith(makePayload([], []));
    const { container } = await renderComponent();

    expect(container.querySelector("[data-rbt-state=\"no-exposure\"]"))
      .not.toBeNull();
    expect(container.textContent).toContain(
      "No cross-config exposure on file for this server",
    );
    expect(container.textContent).toContain("Demo Server");

    // Neither sub-section renders.
    expect(container.querySelector(".rbt-pattern")).toBeNull();
    expect(container.querySelector(".rbt-chain")).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. API 404 → "data unavailable" panel
// ═══════════════════════════════════════════════════════════════════════════

describe("API 404 / network failure", () => {
  it("404 → 'Risk boundary data unavailable for this scan' panel", async () => {
    mockFetchStatus(404);
    const { container } = await renderComponent();
    expect(container.querySelector("[data-rbt-state=\"unavailable\"]"))
      .not.toBeNull();
    expect(container.textContent).toContain(
      "Risk boundary data unavailable for this scan",
    );
    // No pattern/chain sections render at all.
    expect(container.querySelector(".rbt-pattern")).toBeNull();
    expect(container.querySelector(".rbt-chain")).toBeNull();
  });

  it("network throw → unavailable panel (same shape, never crash)", async () => {
    mockFetchThrows();
    const { container } = await renderComponent();
    expect(container.querySelector("[data-rbt-state=\"unavailable\"]"))
      .not.toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. sample_pairings — capped at 5; absent when 0
// ═══════════════════════════════════════════════════════════════════════════

describe("sample_pairings rendering", () => {
  it("when API ships 5 pairings, all 5 render as anchors to /servers/<slug>", async () => {
    const five: RiskBoundaryPattern = makePattern({
      sample_pairings: [
        { slug: "alpha", name: "Alpha" },
        { slug: "beta",  name: "Beta"  },
        { slug: "gamma", name: "Gamma" },
        { slug: "delta", name: "Delta" },
        { slug: "epsilon", name: "Epsilon" },
      ],
      paired_with_count: 5,
    });
    mockFetchWith(makePayload([five], []));
    const { container } = await renderComponent();

    const pairings = container.querySelectorAll(".rbt-pairing");
    expect(pairings).toHaveLength(5);

    const hrefs = Array.from(pairings).map((a) => a.getAttribute("href"));
    expect(hrefs).toEqual([
      "/servers/alpha",
      "/servers/beta",
      "/servers/gamma",
      "/servers/delta",
      "/servers/epsilon",
    ]);
  });

  it("when API ships 0 pairings, no .rbt-pairings list renders", async () => {
    const zero: RiskBoundaryPattern = makePattern({
      sample_pairings: [],
      paired_with_count: 0,
    });
    mockFetchWith(makePayload([zero], []));
    const { container } = await renderComponent();

    // Pattern row itself still renders (count=0 is a real signal).
    expect(container.querySelector(".rbt-pattern")).not.toBeNull();
    // But the pairings list does NOT render (we only show it when there are
    // real pairings).
    expect(container.querySelector(".rbt-pairings")).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. Severity tints — class names map by severity literal
// ═══════════════════════════════════════════════════════════════════════════

describe("severity tints", () => {
  it("each pattern carries the rbt-pattern-<severity> class", async () => {
    const patterns: RiskBoundaryPattern[] = [
      makePattern({ pattern_id: "P01", severity: "critical" }),
      makePattern({ pattern_id: "P02", severity: "high" }),
      makePattern({ pattern_id: "P03", severity: "medium" }),
      makePattern({ pattern_id: "P04", severity: "low" }),
    ];
    mockFetchWith(makePayload(patterns, []));
    const { container } = await renderComponent();

    const p01 = container.querySelector("[data-pattern-id=\"P01\"]");
    const p02 = container.querySelector("[data-pattern-id=\"P02\"]");
    const p03 = container.querySelector("[data-pattern-id=\"P03\"]");
    const p04 = container.querySelector("[data-pattern-id=\"P04\"]");

    expect(p01?.classList.contains("rbt-pattern-critical")).toBe(true);
    expect(p02?.classList.contains("rbt-pattern-high")).toBe(true);
    expect(p03?.classList.contains("rbt-pattern-medium")).toBe(true);
    expect(p04?.classList.contains("rbt-pattern-low")).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. contributing_rule_ids render as visible badges
// ═══════════════════════════════════════════════════════════════════════════

describe("contributing rule ids", () => {
  it("renders one badge per rule id, linked to a finding hash anchor", async () => {
    const chain = makeChain({
      contributing_rule_ids: ["A1", "F1", "G1", "K14"],
    });
    mockFetchWith(makePayload([], [chain]));
    const { container } = await renderComponent();

    const badges = container.querySelectorAll(".rbt-chain-rule");
    expect(badges).toHaveLength(4);
    const labels = Array.from(badges).map((b) => b.textContent);
    expect(labels).toEqual(["A1", "F1", "G1", "K14"]);

    // Anchors point to per-finding hashes (deep-link path parked).
    const hrefs = Array.from(badges).map((b) => b.getAttribute("href"));
    expect(hrefs).toContain("#finding-A1");
    expect(hrefs).toContain("#finding-K14");
  });

  it("when contributing_rule_ids is empty, the rules block does not render", async () => {
    const chain = makeChain({ contributing_rule_ids: [] });
    mockFetchWith(makePayload([], [chain]));
    const { container } = await renderComponent();
    // Chain card is present
    expect(container.querySelector(".rbt-chain")).not.toBeNull();
    // But the rules block is not.
    expect(container.querySelector("[data-rbt-block=\"rules\"]")).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 7. cve_evidence_ids and mitigations render as separate sections per chain
// ═══════════════════════════════════════════════════════════════════════════

describe("cve_evidence_ids and mitigations", () => {
  it("renders distinct CVE block + Mitigations block when both populated", async () => {
    const chain = makeChain({
      cve_evidence_ids: ["CVE-2025-6514", "CVE-2025-53109"],
      mitigations: [
        "Disable autonomous tool chaining.",
        "Require human-in-the-loop approval for sender tools.",
      ],
    });
    mockFetchWith(makePayload([], [chain]));
    const { container } = await renderComponent();

    const cveBlock = container.querySelector("[data-rbt-block=\"cves\"]");
    const mitBlock = container.querySelector("[data-rbt-block=\"mitigations\"]");
    expect(cveBlock).not.toBeNull();
    expect(mitBlock).not.toBeNull();

    // Two distinct anchor blocks: rules (none here) vs cves.
    const cves = container.querySelectorAll(".rbt-chain-cve");
    expect(cves).toHaveLength(2);
    expect(cves[0].textContent).toBe("CVE-2025-6514");
    expect(cves[0].getAttribute("href"))
      .toBe("https://nvd.nist.gov/vuln/detail/CVE-2025-6514");

    // Mitigations as a UL with 2 LIs.
    const mits = container.querySelectorAll(".rbt-chain-mit");
    expect(mits).toHaveLength(2);
    expect(mits[0].textContent).toContain("Disable autonomous tool chaining");
    expect(mits[1].textContent).toContain("Require human-in-the-loop");
  });

  it("renders mitigations block when CVE evidence is empty (independence)", async () => {
    const chain = makeChain({
      cve_evidence_ids: [],
      mitigations: ["Single mitigation."],
    });
    mockFetchWith(makePayload([], [chain]));
    const { container } = await renderComponent();
    expect(container.querySelector("[data-rbt-block=\"cves\"]")).toBeNull();
    expect(container.querySelector("[data-rbt-block=\"mitigations\"]")).not.toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 8. Accessibility — severity gauge has role="img" + descriptive aria-label
// ═══════════════════════════════════════════════════════════════════════════

describe("accessibility", () => {
  it("severity gauge carries role=img and a descriptive aria-label", async () => {
    const chain = makeChain({ severity_score: 73 });
    mockFetchWith(makePayload([], [chain]));
    const { container } = await renderComponent();

    const gauge = container.querySelector(".rbt-chain-gauge") as HTMLElement | null;
    expect(gauge).not.toBeNull();
    expect(gauge!.getAttribute("role")).toBe("img");
    const label = gauge!.getAttribute("aria-label") ?? "";
    expect(label).toContain("73");
    expect(label).toContain("100");
    // Band classification reflected in label
    expect(label.toLowerCase()).toContain("high");
  });

  it("clamps severity score into 0..100 for the gauge fill width", async () => {
    const chain1 = makeChain({ kc_id: "KC01", severity_score: -50 });
    const chain2 = makeChain({ kc_id: "KC02", severity_score: 9999 });
    mockFetchWith(makePayload([], [chain1, chain2]));
    const { container } = await renderComponent();

    const fills = container.querySelectorAll(".rbt-chain-gauge-fill");
    expect(fills.length).toBe(2);
    expect((fills[0] as HTMLElement).style.width).toBe("0%");
    expect((fills[1] as HTMLElement).style.width).toBe("100%");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Extras — header structure regression spot
// ═══════════════════════════════════════════════════════════════════════════

describe("header structure", () => {
  it("renders 'Risk Boundary' title and the cross-config eyebrow", async () => {
    mockFetchWith(makePayload([makePattern()], []));
    const { container } = await renderComponent();
    expect(container.textContent).toContain("Risk Boundary");
    expect(container.textContent).toContain("CROSS-CONFIG EXPOSURE");
  });
});
