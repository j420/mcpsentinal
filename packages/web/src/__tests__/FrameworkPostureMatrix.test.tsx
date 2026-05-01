// @vitest-environment jsdom
/**
 * FrameworkPostureMatrix Test Suite
 *
 * The component is an async Server Component that consumes the frozen contract
 * `GET /api/v1/servers/:slug/compliance`. These tests stub `fetch` directly
 * (the same pattern AttackChainCard / EvidenceChainViz tests cannot use because
 * they are pure components — here we are testing data-driven RSC behavior).
 *
 * Coverage required by Cluster B briefing (8 cases minimum):
 *   1. all 7 frameworks render in API order with correct names + versions
 *   2. status bar segment widths are proportional to controls counts
 *   3. honest-gap (not_applicable > 0) is rendered, NOT hidden
 *   4. per-framework download_paths.{pdf,html,json,badge_svg} → 4 anchor tags
 *   5. aria-label on status bar contains the readable breakdown
 *   6. API 404 → fallback OWASP section renders (when fallback prop provided)
 *   7. API success → no fallback section renders even if fallback prop provided
 *   8. "X of Y controls met across Z frameworks" summary is computed correctly
 *
 * Plus extras for resilience:
 *   - API 404 with no fallback → "Posture unavailable" panel renders
 *   - Empty frameworks[] array → fallback / unavailable behavior
 *   - Network failure (fetch throws) → fallback path
 *   - Per-row data attributes carry framework_id verbatim
 *   - Verbatim API names are NEVER relabeled client-side
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import React from "react";
import { render } from "@testing-library/react";
import FrameworkPostureMatrix, {
  type FrameworkPostureData,
  type FrameworkPostureRow,
} from "../components/FrameworkPostureMatrix";

// ── Helpers ────────────────────────────────────────────────────────────────

const API_URL = "https://api.mcp-sentinel.test";
const SLUG = "demo-server";

function makeRow(overrides: Partial<FrameworkPostureRow> = {}): FrameworkPostureRow {
  const base: FrameworkPostureRow = {
    framework_id: "eu_ai_act",
    framework_name: "EU AI Act",
    framework_version: "2024/1689",
    controls: { met: 4, partial: 1, unmet: 1, not_applicable: 0, total: 6 },
    overall_status: "partial",
    coverage_band: "high",
    download_paths: {
      pdf: "/api/v1/servers/demo-server/compliance/eu_ai_act.pdf",
      html: "/api/v1/servers/demo-server/compliance/eu_ai_act.html",
      json: "/api/v1/servers/demo-server/compliance/eu_ai_act.json",
      badge_svg: "/api/v1/servers/demo-server/compliance/eu_ai_act/badge.svg",
    },
  };
  return { ...base, ...overrides };
}

function makePayload(frameworks: FrameworkPostureRow[]): FrameworkPostureData {
  return {
    server_slug: SLUG,
    server_name: "Demo Server",
    last_assessed_at: "2026-04-30T12:00:00.000Z",
    rules_version: "v2026-04-22",
    frameworks,
  };
}

const ALL_SEVEN: FrameworkPostureRow[] = [
  makeRow({
    framework_id: "eu_ai_act",
    framework_name: "EU AI Act",
    framework_version: "2024/1689",
    controls: { met: 5, partial: 0, unmet: 0, not_applicable: 0, total: 5 },
    overall_status: "met",
    coverage_band: "high",
    download_paths: {
      pdf: "/eu_ai_act.pdf", html: "/eu_ai_act.html",
      json: "/eu_ai_act.json", badge_svg: "/eu_ai_act/badge.svg",
    },
  }),
  makeRow({
    framework_id: "iso_27001",
    framework_name: "ISO/IEC 27001",
    framework_version: "2022",
    controls: { met: 8, partial: 2, unmet: 0, not_applicable: 0, total: 10 },
    overall_status: "partial",
    coverage_band: "high",
    download_paths: {
      pdf: "/iso_27001.pdf", html: "/iso_27001.html",
      json: "/iso_27001.json", badge_svg: "/iso_27001/badge.svg",
    },
  }),
  makeRow({
    framework_id: "owasp_mcp",
    framework_name: "OWASP MCP Top 10",
    framework_version: "2025",
    controls: { met: 7, partial: 1, unmet: 2, not_applicable: 0, total: 10 },
    overall_status: "unmet",
    coverage_band: "high",
    download_paths: {
      pdf: "/owasp_mcp.pdf", html: "/owasp_mcp.html",
      json: "/owasp_mcp.json", badge_svg: "/owasp_mcp/badge.svg",
    },
  }),
  makeRow({
    framework_id: "owasp_asi",
    framework_name: "OWASP Agentic Applications Security Top 10",
    framework_version: "2025-12",
    // not_applicable=1 here is the HONEST GAP (ASI10 — out of scope for an MCP scanner)
    controls: { met: 6, partial: 2, unmet: 1, not_applicable: 1, total: 10 },
    overall_status: "partial",
    coverage_band: "high",
    download_paths: {
      pdf: "/owasp_asi.pdf", html: "/owasp_asi.html",
      json: "/owasp_asi.json", badge_svg: "/owasp_asi/badge.svg",
    },
  }),
  makeRow({
    framework_id: "cosai_mcp",
    framework_name: "CoSAI MCP Security Threat Taxonomy",
    framework_version: "2026-01",
    controls: { met: 9, partial: 1, unmet: 2, not_applicable: 0, total: 12 },
    overall_status: "partial",
    coverage_band: "high",
    download_paths: {
      pdf: "/cosai_mcp.pdf", html: "/cosai_mcp.html",
      json: "/cosai_mcp.json", badge_svg: "/cosai_mcp/badge.svg",
    },
  }),
  makeRow({
    framework_id: "maestro",
    framework_name: "MAESTRO Multi-Agent Threat Model",
    framework_version: "2025-02",
    controls: { met: 4, partial: 1, unmet: 0, not_applicable: 0, total: 5 },
    overall_status: "partial",
    coverage_band: "medium",
    download_paths: {
      pdf: "/maestro.pdf", html: "/maestro.html",
      json: "/maestro.json", badge_svg: "/maestro/badge.svg",
    },
  }),
  makeRow({
    framework_id: "mitre_atlas",
    framework_name: "MITRE ATLAS",
    framework_version: "v5.0",
    controls: { met: 7, partial: 2, unmet: 0, not_applicable: 0, total: 9 },
    overall_status: "partial",
    coverage_band: "high",
    download_paths: {
      pdf: "/mitre_atlas.pdf", html: "/mitre_atlas.html",
      json: "/mitre_atlas.json", badge_svg: "/mitre_atlas/badge.svg",
    },
  }),
];

function mockFetchWith(payload: FrameworkPostureData, status = 200): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      return {
        ok: status >= 200 && status < 300,
        status,
        json: async () => ({ data: payload }),
      } as Response;
    })
  );
}

function mockFetchStatus(status: number): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      return {
        ok: status >= 200 && status < 300,
        status,
        json: async () => ({ error: "not found" }),
      } as Response;
    })
  );
}

function mockFetchThrows(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      throw new Error("network broken");
    })
  );
}

async function renderComponent(props: {
  owasp_coverage_fallback?: Record<string, boolean> | null;
} = {}) {
  const node = await FrameworkPostureMatrix({
    slug: SLUG,
    apiUrl: API_URL,
    owasp_coverage_fallback: props.owasp_coverage_fallback,
  });
  return render(node);
}

beforeEach(() => {
  // Each test sets its own fetch stub.
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

// ═══════════════════════════════════════════════════════════════════════════
// 1. All 7 frameworks render in API order with correct names + versions
// ═══════════════════════════════════════════════════════════════════════════

describe("renders all 7 frameworks in API order with correct names + versions", () => {
  it("renders one row per framework, in the order returned by the API", async () => {
    mockFetchWith(makePayload(ALL_SEVEN));
    const { container } = await renderComponent();

    const rows = container.querySelectorAll(".fpm-row");
    expect(rows).toHaveLength(7);

    // Order must match the API payload exactly — never re-sort client-side.
    const ids = Array.from(rows).map((r) => r.getAttribute("data-framework-id"));
    expect(ids).toEqual([
      "eu_ai_act",
      "iso_27001",
      "owasp_mcp",
      "owasp_asi",
      "cosai_mcp",
      "maestro",
      "mitre_atlas",
    ]);

    // Every framework name + version renders verbatim from the API payload.
    for (const fw of ALL_SEVEN) {
      expect(container.textContent).toContain(fw.framework_name);
      expect(container.textContent).toContain(fw.framework_version);
    }
  });

  it("never relabels framework names client-side (regulator-grade language audit)", async () => {
    // Pretend the API ships an unusual capitalization. The component must
    // render that string verbatim — DR-001 lesson: language must match the
    // source-of-truth registry exactly.
    const oddName = "EU AI Act (preview rev.)";
    const oddVer = "2025/2222";
    mockFetchWith(
      makePayload([
        makeRow({
          framework_id: "eu_ai_act",
          framework_name: oddName,
          framework_version: oddVer,
        }),
      ])
    );
    const { container } = await renderComponent();
    expect(container.textContent).toContain(oddName);
    expect(container.textContent).toContain(oddVer);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. Status bar segment widths are proportional to control counts
// ═══════════════════════════════════════════════════════════════════════════

describe("status bar segment widths are proportional to control counts", () => {
  it("met=5 partial=2 unmet=2 not_applicable=1 total=10 → 50/20/20/10 percent", async () => {
    mockFetchWith(
      makePayload([
        makeRow({
          controls: { met: 5, partial: 2, unmet: 2, not_applicable: 1, total: 10 },
        }),
      ])
    );
    const { container } = await renderComponent();

    const met = container.querySelector(".fpm-bar-met") as HTMLElement | null;
    const partial = container.querySelector(".fpm-bar-partial") as HTMLElement | null;
    const unmet = container.querySelector(".fpm-bar-unmet") as HTMLElement | null;
    const na = container.querySelector(".fpm-bar-not_applicable") as HTMLElement | null;

    expect(met?.style.width).toBe("50%");
    expect(partial?.style.width).toBe("20%");
    expect(unmet?.style.width).toBe("20%");
    expect(na?.style.width).toBe("10%");
  });

  it("zero-count segments are not rendered inside the bar (no DOM noise)", async () => {
    mockFetchWith(
      makePayload([
        makeRow({
          controls: { met: 10, partial: 0, unmet: 0, not_applicable: 0, total: 10 },
        }),
      ])
    );
    const { container } = await renderComponent();

    // Scope to inside the actual status bar (not the legend swatches which
    // intentionally show all four colors as a key).
    const bar = container.querySelector(".fpm-bar") as HTMLElement | null;
    expect(bar).not.toBeNull();
    expect(bar!.querySelector(".fpm-bar-met")).not.toBeNull();
    expect(bar!.querySelector(".fpm-bar-partial")).toBeNull();
    expect(bar!.querySelector(".fpm-bar-unmet")).toBeNull();
    expect(bar!.querySelector(".fpm-bar-not_applicable")).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. Honest-gap (not_applicable > 0) MUST render, NOT be hidden
// ═══════════════════════════════════════════════════════════════════════════

describe("honest gaps render visibly", () => {
  it("not_applicable=3 → segment present in DOM with non-zero width", async () => {
    mockFetchWith(
      makePayload([
        makeRow({
          controls: { met: 5, partial: 0, unmet: 2, not_applicable: 3, total: 10 },
        }),
      ])
    );
    const { container } = await renderComponent();

    const naSegment = container.querySelector(".fpm-bar-not_applicable") as HTMLElement | null;
    expect(naSegment).not.toBeNull();
    expect(naSegment!.style.width).toBe("30%");

    // The numeric counts column also shows the not_applicable count.
    const naCount = container.querySelector(".fpm-count-na");
    expect(naCount).not.toBeNull();
    expect(naCount!.textContent).toBe("3");
  });

  it("ASI10-style honest gap (not_applicable=1, total=10) is visible to the eye", async () => {
    mockFetchWith(
      makePayload([
        makeRow({
          framework_id: "owasp_asi",
          framework_name: "OWASP Agentic Applications Security Top 10",
          framework_version: "2025-12",
          controls: { met: 7, partial: 1, unmet: 1, not_applicable: 1, total: 10 },
          overall_status: "partial",
        }),
      ])
    );
    const { container } = await renderComponent();
    const naSegment = container.querySelector(".fpm-bar-not_applicable") as HTMLElement | null;
    expect(naSegment).not.toBeNull();
    expect(naSegment!.style.width).toBe("10%");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. Per-framework download_paths.{pdf,html,json,badge_svg} → 4 anchor tags
// ═══════════════════════════════════════════════════════════════════════════

describe("download links render verbatim from download_paths", () => {
  it("renders 4 anchor tags per framework with the exact href values from the API", async () => {
    mockFetchWith(
      makePayload([
        makeRow({
          framework_id: "eu_ai_act",
          framework_name: "EU AI Act",
          download_paths: {
            pdf: "/p1.pdf",
            html: "/p1.html",
            json: "/p1.json",
            badge_svg: "/p1/badge.svg",
          },
        }),
      ])
    );
    const { container } = await renderComponent();
    const anchors = container.querySelectorAll(".fpm-row a.fpm-dl");
    expect(anchors).toHaveLength(4);
    const hrefs = Array.from(anchors).map((a) => a.getAttribute("href"));
    expect(hrefs).toContain("/p1.pdf");
    expect(hrefs).toContain("/p1.html");
    expect(hrefs).toContain("/p1.json");
    expect(hrefs).toContain("/p1/badge.svg");
  });

  it("with 7 frameworks renders 28 download anchors (7 × 4)", async () => {
    mockFetchWith(makePayload(ALL_SEVEN));
    const { container } = await renderComponent();
    const anchors = container.querySelectorAll("a.fpm-dl");
    expect(anchors).toHaveLength(28);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. aria-label on status bar contains the readable breakdown
// ═══════════════════════════════════════════════════════════════════════════

describe("status bar accessibility", () => {
  it("aria-label on .fpm-bar describes met / partial / unmet / not_applicable / total in plain language", async () => {
    mockFetchWith(
      makePayload([
        makeRow({
          framework_name: "EU AI Act",
          controls: { met: 4, partial: 1, unmet: 2, not_applicable: 3, total: 10 },
        }),
      ])
    );
    const { container } = await renderComponent();
    const bar = container.querySelector(".fpm-bar") as HTMLElement | null;
    expect(bar).not.toBeNull();
    expect(bar!.getAttribute("role")).toBe("img");
    const label = bar!.getAttribute("aria-label") ?? "";
    expect(label).toContain("EU AI Act");
    expect(label).toContain("4 met");
    expect(label).toContain("1 partial");
    expect(label).toContain("2 unmet");
    expect(label).toContain("3 not applicable");
    expect(label).toContain("of 10 total");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. API 404 → fallback OWASP section renders (when fallback prop provided)
// ═══════════════════════════════════════════════════════════════════════════

describe("fallback when the new endpoint is not deployed yet", () => {
  it("API 404 + owasp_coverage_fallback provided → OWASP grid renders", async () => {
    mockFetchStatus(404);
    const { container } = await renderComponent({
      owasp_coverage_fallback: {
        MCP01: true,
        MCP02: false,
        MCP03: true,
      },
    });
    expect(container.querySelector("[data-fpm-fallback=\"owasp\"]")).not.toBeNull();
    expect(container.querySelector(".sd-owasp-grid")).not.toBeNull();
    // Old grid content present.
    expect(container.textContent).toContain("OWASP MCP Top 10 Coverage");
    expect(container.textContent).toContain("Prompt Injection");
    expect(container.textContent).toContain("Tool Poisoning");
    // The new matrix did NOT render (no .fpm-matrix node).
    expect(container.querySelector(".fpm-matrix")).toBeNull();
  });

  it("API 404 + no fallback → 'Posture unavailable for this scan' panel", async () => {
    mockFetchStatus(404);
    const { container } = await renderComponent({});
    expect(container.querySelector("[data-fpm-state=\"unavailable\"]")).not.toBeNull();
    expect(container.textContent).toContain("Posture unavailable for this scan");
    expect(container.querySelector(".fpm-empty")).not.toBeNull();
  });

  it("network error (fetch throws) + fallback provided → OWASP grid renders", async () => {
    mockFetchThrows();
    const { container } = await renderComponent({
      owasp_coverage_fallback: { MCP01: true, MCP02: false },
    });
    expect(container.querySelector("[data-fpm-fallback=\"owasp\"]")).not.toBeNull();
  });

  it("API returns empty frameworks[] + fallback provided → OWASP grid renders", async () => {
    mockFetchWith(makePayload([]));
    const { container } = await renderComponent({
      owasp_coverage_fallback: { MCP01: true },
    });
    expect(container.querySelector("[data-fpm-fallback=\"owasp\"]")).not.toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 7. API success → fallback section is suppressed even if fallback prop given
// ═══════════════════════════════════════════════════════════════════════════

describe("fallback is suppressed when API success", () => {
  it("API success + owasp_coverage_fallback provided → no OWASP fallback section renders", async () => {
    mockFetchWith(makePayload(ALL_SEVEN));
    const { container } = await renderComponent({
      owasp_coverage_fallback: {
        MCP01: true,
        MCP02: false,
        MCP03: true,
      },
    });
    // New matrix renders.
    expect(container.querySelector(".fpm-matrix")).not.toBeNull();
    // Legacy fallback does NOT render.
    expect(container.querySelector("[data-fpm-fallback=\"owasp\"]")).toBeNull();
    expect(container.querySelector(".sd-owasp-grid")).toBeNull();
    // Section state attribute confirms ok path.
    expect(container.querySelector("[data-fpm-state=\"ok\"]")).not.toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 8. "X of Y controls met across Z frameworks" summary computed correctly
// ═══════════════════════════════════════════════════════════════════════════

describe("summary line", () => {
  it("computes total met + total controls across frameworks correctly", async () => {
    // ALL_SEVEN: met = 5+8+7+6+9+4+7 = 46; total = 5+10+10+10+12+5+9 = 61; n=7
    mockFetchWith(makePayload(ALL_SEVEN));
    const { container } = await renderComponent();
    const summary = container.querySelector("[data-fpm-summary]");
    expect(summary).not.toBeNull();
    expect(summary!.textContent).toContain("46 of 61 controls met across 7 frameworks");
  });

  it("singular 'framework' when frameworks.length === 1", async () => {
    mockFetchWith(
      makePayload([
        makeRow({
          controls: { met: 3, partial: 0, unmet: 0, not_applicable: 0, total: 3 },
        }),
      ])
    );
    const { container } = await renderComponent();
    const summary = container.querySelector("[data-fpm-summary]");
    expect(summary!.textContent).toContain("3 of 3 controls met across 1 framework");
    expect(summary!.textContent).not.toContain("frameworks");
  });

  it("includes a relative-time phrase for last_assessed_at", async () => {
    const payload = makePayload(ALL_SEVEN);
    payload.last_assessed_at = new Date().toISOString();
    mockFetchWith(payload);
    const { container } = await renderComponent();
    const summary = container.querySelector("[data-fpm-summary]");
    expect(summary!.textContent).toMatch(/(just now|minute|hour|day|month|year)/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Extras — header structure + count column
// ═══════════════════════════════════════════════════════════════════════════

describe("header structure", () => {
  it("renders 'Framework Posture' title and 'REGULATOR-FACING' eyebrow", async () => {
    mockFetchWith(makePayload(ALL_SEVEN));
    const { container } = await renderComponent();
    expect(container.textContent).toContain("Framework Posture");
    expect(container.textContent).toContain("REGULATOR-FACING");
  });

  it("section count badge equals frameworks.length", async () => {
    mockFetchWith(makePayload(ALL_SEVEN));
    const { container } = await renderComponent();
    const count = container.querySelector(".sd-section-count");
    expect(count).not.toBeNull();
    expect(count!.textContent).toBe("7");
  });

  it("each row exposes overall status pill text from API status verbatim", async () => {
    mockFetchWith(
      makePayload([
        makeRow({ overall_status: "met" }),
        makeRow({ framework_id: "iso_27001", framework_name: "ISO/IEC 27001", framework_version: "2022", overall_status: "unmet" }),
      ])
    );
    const { container } = await renderComponent();
    const pills = container.querySelectorAll(".fpm-status-pill");
    expect(pills).toHaveLength(2);
    expect(pills[0].textContent).toBe("Met");
    expect(pills[1].textContent).toBe("Unmet");
  });
});
