// @vitest-environment jsdom
/**
 * DriftAndHistoryTab Test Suite
 *
 * Async Server Component consumes
 *   GET /api/v1/servers/:slug/drift?days=<N>
 *
 * Coverage required by Cluster C briefing (8 cases minimum):
 *   1. happy path with mixed headlines → kind glyphs + severity tints correct
 *   2. headlines:[] with non-empty score_history → "no drift in last N days"
 *      message
 *   3. trend === "insufficient_data" → explicit panel
 *   4. all 4 trend chip color mappings (good/critical/text-2/text-3 + special note)
 *   5. ?days=30 in props threads to fetch URL
 *   6. score sparkline renders an SVG with the correct number of points
 *   7. ref.from / ref.to render in the subline when present
 *   8. API 404 → "drift data unavailable" panel
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import React from "react";
import { render } from "@testing-library/react";
import DriftAndHistoryTab, {
  type DriftAndHistoryData,
  type DriftHeadline,
  type DriftScorePoint,
  fmtRelativeTime,
} from "../components/DriftAndHistoryTab";

const API_URL = "https://api.mcp-sentinel.test";
const SLUG = "demo-server";

// ── Helpers ────────────────────────────────────────────────────────────────

function makeHeadline(overrides: Partial<DriftHeadline> = {}): DriftHeadline {
  return {
    kind: "tool_added",
    severity_hint: "elevated",
    occurred_at: "2026-04-29T12:00:00.000Z",
    summary: "New tool added: write_file",
    ...overrides,
  };
}

function makePoint(score: number, hoursAgo: number): DriftScorePoint {
  return {
    scanned_at: new Date(Date.now() - hoursAgo * 3_600_000).toISOString(),
    score,
  };
}

function makePayload(overrides: Partial<DriftAndHistoryData> = {}): DriftAndHistoryData {
  return {
    server_slug: SLUG,
    window_days: 90,
    headlines: [makeHeadline()],
    score_history: [makePoint(80, 240), makePoint(75, 24)],
    trend: "neutral",
    ...overrides,
  };
}

let lastFetchUrl = "";

function mockFetchWith(payload: DriftAndHistoryData, status = 200): void {
  lastFetchUrl = "";
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL | Request) => {
      lastFetchUrl =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : (input as Request).url;
      return {
        ok: status >= 200 && status < 300,
        status,
        json: async () => ({ data: payload }),
      } as Response;
    }),
  );
}

function mockFetchStatus(status: number): void {
  lastFetchUrl = "";
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL | Request) => {
      lastFetchUrl =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : (input as Request).url;
      return {
        ok: status >= 200 && status < 300,
        status,
        json: async () => ({ error: "not found" }),
      } as Response;
    }),
  );
}

async function renderComponent(props: { days?: number } = {}) {
  const node = await DriftAndHistoryTab({
    slug: SLUG,
    apiUrl: API_URL,
    days: props.days,
  });
  return render(node);
}

beforeEach(() => {});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

// ═══════════════════════════════════════════════════════════════════════════
// 1. Happy path with mixed headlines — kind glyphs + severity tints correct
// ═══════════════════════════════════════════════════════════════════════════

describe("happy path with mixed headlines", () => {
  it("renders one row per kind with the correct glyph + severity tint class", async () => {
    const headlines: DriftHeadline[] = [
      makeHeadline({
        kind: "tool_added",
        severity_hint: "elevated",
        summary: "New tool: write_file",
        occurred_at: "2026-04-30T10:00:00.000Z",
      }),
      makeHeadline({
        kind: "tool_removed",
        severity_hint: "neutral",
        summary: "Removed tool: list_dir",
        occurred_at: "2026-04-29T10:00:00.000Z",
      }),
      makeHeadline({
        kind: "tool_description_changed",
        severity_hint: "elevated",
        summary: "Description changed: search",
        occurred_at: "2026-04-28T10:00:00.000Z",
      }),
      makeHeadline({
        kind: "capability_added",
        severity_hint: "elevated",
        summary: "Capability added: writes-data",
        occurred_at: "2026-04-27T10:00:00.000Z",
      }),
      makeHeadline({
        kind: "dangerous_capability_introduced",
        severity_hint: "degrading",
        summary: "Dangerous capability introduced: executes-code",
        occurred_at: "2026-04-26T10:00:00.000Z",
      }),
      makeHeadline({
        kind: "score_changed",
        severity_hint: "improving",
        summary: "Score 70 → 78",
        occurred_at: "2026-04-25T10:00:00.000Z",
      }),
    ];
    mockFetchWith(makePayload({ headlines, trend: "improving" }));
    const { container } = await renderComponent();

    const rows = container.querySelectorAll(".dah-headline");
    expect(rows).toHaveLength(6);

    // Kind glyphs: + − ≈ ▸ ⚠ △
    const glyphs = Array.from(container.querySelectorAll(".dah-glyph")).map(
      (g) => g.textContent,
    );
    expect(glyphs).toContain("+");
    expect(glyphs).toContain("−");
    expect(glyphs).toContain("≈");
    expect(glyphs).toContain("▸");
    expect(glyphs).toContain("⚠");
    expect(glyphs).toContain("△");

    // Severity tints: each row carries dah-headline-<severity_hint>.
    expect(container.querySelector(".dah-headline-elevated")).not.toBeNull();
    expect(container.querySelector(".dah-headline-degrading")).not.toBeNull();
    expect(container.querySelector(".dah-headline-improving")).not.toBeNull();
    expect(container.querySelector(".dah-headline-neutral")).not.toBeNull();

    // Most recent first — sort defensively.
    const firstSummary = rows[0]!.querySelector(".dah-headline-summary")?.textContent;
    expect(firstSummary).toContain("New tool: write_file");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. headlines:[] but score_history non-empty → "no drift" message
// ═══════════════════════════════════════════════════════════════════════════

describe("no drift but score history present", () => {
  it("renders 'no tool-set drift in the last N days' message", async () => {
    mockFetchWith(makePayload({
      headlines: [],
      window_days: 30,
      trend: "neutral",
      score_history: [makePoint(80, 240), makePoint(80, 24)],
    }));
    const { container } = await renderComponent();

    const msg = container.querySelector("[data-dah-no-drift]");
    expect(msg).not.toBeNull();
    expect(msg!.textContent).toContain("No tool-set drift in the last 30 days");

    // Sparkline still renders.
    expect(container.querySelector("[data-dah-sparkline]")).not.toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. trend === "insufficient_data" → explicit panel
// ═══════════════════════════════════════════════════════════════════════════

describe("insufficient data", () => {
  it("renders the explicit insufficient-data panel", async () => {
    mockFetchWith(makePayload({
      trend: "insufficient_data",
      headlines: [],
      score_history: [makePoint(80, 1)], // 1 point
    }));
    const { container } = await renderComponent();

    expect(container.querySelector("[data-dah-state=\"insufficient-data\"]"))
      .not.toBeNull();
    expect(container.textContent).toContain("Not enough scan history yet");
    expect(container.textContent).toContain("at least 2 scans");

    // Trend chip carries the right data attribute.
    const chip = container.querySelector("[data-dah-trend=\"insufficient_data\"]");
    expect(chip).not.toBeNull();
    expect(chip!.textContent).toContain("INSUFFICIENT DATA");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. All 4 trend chip color mappings
// ═══════════════════════════════════════════════════════════════════════════

describe("trend chip color mappings", () => {
  async function renderTrend(trend: DriftAndHistoryData["trend"]) {
    mockFetchWith(makePayload({ trend }));
    const { container } = await renderComponent();
    return container;
  }

  it("improving → --good", async () => {
    const c = await renderTrend("improving");
    const chip = c.querySelector("[data-dah-trend=\"improving\"]") as HTMLElement | null;
    expect(chip).not.toBeNull();
    expect(chip!.style.color).toContain("--good");
    expect(chip!.classList.contains("dah-trend-improving")).toBe(true);
  });

  it("degrading → --critical", async () => {
    const c = await renderTrend("degrading");
    const chip = c.querySelector("[data-dah-trend=\"degrading\"]") as HTMLElement | null;
    expect(chip).not.toBeNull();
    expect(chip!.style.color).toContain("--critical");
  });

  it("neutral → --text-2", async () => {
    const c = await renderTrend("neutral");
    const chip = c.querySelector("[data-dah-trend=\"neutral\"]") as HTMLElement | null;
    expect(chip).not.toBeNull();
    expect(chip!.style.color).toContain("--text-2");
  });

  it("insufficient_data → --text-3 + special note panel", async () => {
    mockFetchWith(makePayload({
      trend: "insufficient_data",
      headlines: [],
    }));
    const { container } = await renderComponent();
    const chip = container.querySelector("[data-dah-trend=\"insufficient_data\"]") as HTMLElement | null;
    expect(chip).not.toBeNull();
    expect(chip!.style.color).toContain("--text-3");
    // Special note panel — distinct from the regular ok state.
    expect(container.querySelector("[data-dah-state=\"insufficient-data\"]"))
      .not.toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. ?days=30 props value threads to fetch URL
// ═══════════════════════════════════════════════════════════════════════════

describe("days param threading", () => {
  it("days=30 prop produces ?days=30 in fetch URL", async () => {
    mockFetchWith(makePayload({ window_days: 30 }));
    await renderComponent({ days: 30 });
    expect(lastFetchUrl).toContain("/api/v1/servers/demo-server/drift?days=30");
  });

  it("default (no days) → ?days=90", async () => {
    mockFetchWith(makePayload({ window_days: 90 }));
    await renderComponent();
    expect(lastFetchUrl).toContain("?days=90");
  });

  it("invalid days (e.g. 7) snaps to 90", async () => {
    mockFetchWith(makePayload({ window_days: 90 }));
    await renderComponent({ days: 7 });
    expect(lastFetchUrl).toContain("?days=90");
  });

  it("days=365 also threads through", async () => {
    mockFetchWith(makePayload({ window_days: 365 }));
    await renderComponent({ days: 365 });
    expect(lastFetchUrl).toContain("?days=365");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. Score sparkline renders an SVG with the correct number of points
// ═══════════════════════════════════════════════════════════════════════════

describe("score sparkline", () => {
  it("renders an SVG with one circle per score_history point", async () => {
    const points: DriftScorePoint[] = [
      makePoint(80, 720),
      makePoint(78, 360),
      makePoint(72, 168),
      makePoint(75, 24),
    ];
    mockFetchWith(makePayload({ score_history: points }));
    const { container } = await renderComponent();

    const svg = container.querySelector("[data-dah-sparkline]") as SVGElement | null;
    expect(svg).not.toBeNull();
    expect(svg!.tagName.toLowerCase()).toBe("svg");
    expect(svg!.getAttribute("data-point-count")).toBe("4");

    const circles = svg!.querySelectorAll("circle");
    expect(circles).toHaveLength(4);

    // A polyline connects ≥2 points.
    const poly = svg!.querySelector("polyline");
    expect(poly).not.toBeNull();

    // Accessibility — sparkline carries role=img and an aria-label.
    expect(svg!.getAttribute("role")).toBe("img");
    expect((svg!.getAttribute("aria-label") ?? "")).toContain("Score history");
  });

  it("when score_history is empty, sparkline subsection does not render", async () => {
    mockFetchWith(makePayload({ score_history: [], headlines: [makeHeadline()] }));
    const { container } = await renderComponent();
    expect(container.querySelector("[data-dah-subsection=\"sparkline\"]")).toBeNull();
    expect(container.querySelector("[data-dah-sparkline]")).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 7. ref.from / ref.to render in the subline when present
// ═══════════════════════════════════════════════════════════════════════════

describe("ref subline rendering", () => {
  it("from + to → 'from → to' rendered as mono spans", async () => {
    const h = makeHeadline({
      kind: "tool_description_changed",
      severity_hint: "elevated",
      summary: "Description changed for read_file",
      ref: { tool_name: "read_file", from: "Reads files.", to: "Reads any path on disk." },
    });
    mockFetchWith(makePayload({ headlines: [h] }));
    const { container } = await renderComponent();

    const ref = container.querySelector("[data-headline-ref]");
    expect(ref).not.toBeNull();
    expect(ref!.textContent).toContain("read_file");
    expect(ref!.textContent).toContain("Reads files.");
    expect(ref!.textContent).toContain("Reads any path on disk.");
    expect(ref!.textContent).toContain("→");
  });

  it("only tool_name (no from/to) → tool name renders, no arrow", async () => {
    const h = makeHeadline({
      kind: "tool_added",
      severity_hint: "elevated",
      summary: "Tool added: list_dir",
      ref: { tool_name: "list_dir" },
    });
    mockFetchWith(makePayload({ headlines: [h] }));
    const { container } = await renderComponent();
    const ref = container.querySelector("[data-headline-ref]");
    expect(ref).not.toBeNull();
    expect(ref!.textContent).toContain("list_dir");
    // No delta arrow when from/to are not provided.
    expect(ref!.querySelector(".dah-ref-arrow")).toBeNull();
  });

  it("absent ref → no subline renders at all", async () => {
    const h = makeHeadline({
      kind: "score_changed",
      severity_hint: "improving",
      summary: "Score improved",
      // explicitly no ref
    });
    mockFetchWith(makePayload({ headlines: [h] }));
    const { container } = await renderComponent();
    expect(container.querySelector("[data-headline-ref]")).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 8. API 404 → 'drift data unavailable' panel
// ═══════════════════════════════════════════════════════════════════════════

describe("API 404", () => {
  it("404 → 'Drift data unavailable for this scan' panel", async () => {
    mockFetchStatus(404);
    const { container } = await renderComponent();
    expect(container.querySelector("[data-dah-state=\"unavailable\"]"))
      .not.toBeNull();
    expect(container.textContent).toContain("Drift data unavailable for this scan");
    // No headline list, no sparkline.
    expect(container.querySelector(".dah-headline")).toBeNull();
    expect(container.querySelector("[data-dah-sparkline]")).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Helper coverage — fmtRelativeTime
// ═══════════════════════════════════════════════════════════════════════════

describe("fmtRelativeTime helper", () => {
  it("returns 'just now' for very recent timestamps", () => {
    const now = Date.now();
    expect(fmtRelativeTime(new Date(now - 1_000).toISOString(), now)).toBe("just now");
  });

  it("returns Nm ago for sub-hour", () => {
    const now = Date.now();
    expect(fmtRelativeTime(new Date(now - 5 * 60_000).toISOString(), now))
      .toBe("5m ago");
  });

  it("returns Nh ago for sub-day", () => {
    const now = Date.now();
    expect(fmtRelativeTime(new Date(now - 3 * 3_600_000).toISOString(), now))
      .toBe("3h ago");
  });

  it("returns Nd ago for sub-month", () => {
    const now = Date.now();
    expect(fmtRelativeTime(new Date(now - 5 * 86_400_000).toISOString(), now))
      .toBe("5d ago");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Header structure regression spot
// ═══════════════════════════════════════════════════════════════════════════

describe("header structure", () => {
  it("renders 'Drift & History' title and 'WHAT CHANGED' eyebrow", async () => {
    mockFetchWith(makePayload());
    const { container } = await renderComponent();
    expect(container.textContent).toContain("Drift");
    expect(container.textContent).toContain("History");
    expect(container.textContent).toContain("WHAT CHANGED");
  });
});
