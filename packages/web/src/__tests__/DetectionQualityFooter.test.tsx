// @vitest-environment jsdom
/**
 * DetectionQualityFooter — three-state render policy + backwards-compat.
 *
 * What this guards (Cluster C Invention #4):
 *   1. State A (full data): precision + recall chips with band-correct colors,
 *      fixture count, CVE chips with NVD hrefs, last_validated_at relative.
 *   2. State B (wired-but-empty): "no fixtures or CVE replays yet" line
 *      renders visibly in muted color — NOT hidden.
 *   3. State C (not wired, detection_quality === null): "not yet wired" line
 *      renders visibly in muted color — NOT hidden, NOT crashed.
 *   4. Backwards-compat: `undefined` → component returns null (renders nothing),
 *      so older API responses produce no regression.
 *   5. Precision/recall band color mapping: 0.95 → good, 0.75 → moderate,
 *      0.60 → poor, null → muted em-dash.
 *   6. CVE chip overflow: 5 ids → 4 visible + "+1 more" with full list in title.
 *   7. CVE chip href: opens nvd.nist.gov for that CVE id, new tab, rel safe.
 *   8. Row click target (states A/B/C all): OWASP MCP signed PDF for slug,
 *      new tab, aria-label phrased as "View signed evidence backing for <id>".
 *   9. Accessibility: aria-label on every interactive chip + on the row itself,
 *      logical reading order (status → label → counts → metrics → freshness).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import React from "react";
import { render } from "@testing-library/react";
import DetectionQualityFooter from "../components/DetectionQualityFooter";
import type { DetectionQuality } from "../lib/detection-quality";

// ── Helpers ─────────────────────────────────────────────────────────────

const SLUG = "example-server";
const API = "http://api.example.test";
const RULE = "K1";

function mountFooter(
  detection_quality: DetectionQuality | null | undefined,
  overrides: { slug?: string; apiUrl?: string; ruleId?: string } = {},
) {
  return render(
    <DetectionQualityFooter
      detection_quality={detection_quality}
      slug={overrides.slug ?? SLUG}
      apiUrl={overrides.apiUrl ?? API}
      ruleId={overrides.ruleId ?? RULE}
    />,
  );
}

const FIXED_NOW = new Date("2026-05-01T12:00:00.000Z").getTime();

beforeEach(() => {
  // Stable "now" so relative-time formatting is deterministic.
  vi.useFakeTimers();
  vi.setSystemTime(FIXED_NOW);
});

afterEach(() => {
  vi.useRealTimers();
});

// ═══════════════════════════════════════════════════════════════════════
// 1. State A — full data
// ═══════════════════════════════════════════════════════════════════════

describe("State A — full validation data", () => {
  it("renders fixtures, CVE chips, p/r metrics, and relative last-validated", () => {
    const dq: DetectionQuality = {
      precision: 0.95,
      recall: 0.88,
      fixture_count: 12,
      cve_replay_ids: ["CVE-2025-6514"],
      // 4 days before FIXED_NOW.
      last_validated_at: "2026-04-27T12:00:00.000Z",
    };
    const { container } = mountFooter(dq);
    const text = container.textContent ?? "";

    expect(container.querySelector(".dqf-row-full")).not.toBeNull();
    expect(text).toContain("Validated");
    expect(text).toContain("12 fixtures");
    expect(text).toContain("CVE-2025-6514");
    expect(text).toContain("0.95");
    expect(text).toContain("0.88");
    expect(text).toContain("last validated 4d ago");

    // Two metric chips (p, r) regardless of band.
    expect(container.querySelectorAll(".dqf-metric")).toHaveLength(2);
    // Singular fixture wording when count is 1 — sanity guard.
    // (12 → "fixtures" with 's').
  });

  it("uses singular 'fixture' when count is exactly 1", () => {
    const dq: DetectionQuality = {
      precision: 0.9,
      recall: 0.9,
      fixture_count: 1,
      cve_replay_ids: [],
      last_validated_at: null,
    };
    const { container } = mountFooter(dq);
    expect(container.textContent).toContain("1 fixture");
    // Make sure we did NOT pluralise.
    expect(container.textContent).not.toContain("1 fixtures");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 2. State B — wired-but-empty
// ═══════════════════════════════════════════════════════════════════════

describe("State B — wired but no validations", () => {
  it("renders the 'no fixtures or CVE replays yet' line, not hidden", () => {
    const dq: DetectionQuality = {
      precision: null,
      recall: null,
      fixture_count: 0,
      cve_replay_ids: [],
      last_validated_at: null,
    };
    const { container } = mountFooter(dq);

    expect(container.querySelector(".dqf-row-empty")).not.toBeNull();
    expect(container.textContent).toContain(
      "Validation framework wired — no fixtures or CVE replays for this rule yet",
    );
    // No metric chips, no CVE chips, no fixture count.
    expect(container.querySelectorAll(".dqf-metric")).toHaveLength(0);
    expect(container.querySelectorAll(".dqf-cve")).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 3. State C — not wired
// ═══════════════════════════════════════════════════════════════════════

describe("State C — detection_quality === null", () => {
  it("renders the 'not yet wired' line, not hidden, not crashed", () => {
    const { container } = mountFooter(null);

    expect(container.querySelector(".dqf-row-unwired")).not.toBeNull();
    expect(container.textContent).toContain(
      "Detection quality not yet wired for this rule",
    );
    // No metrics, no CVEs.
    expect(container.querySelectorAll(".dqf-metric")).toHaveLength(0);
    expect(container.querySelectorAll(".dqf-cve")).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 4. Backwards-compat — undefined renders nothing
// ═══════════════════════════════════════════════════════════════════════

describe("Backwards-compat — detection_quality === undefined", () => {
  it("renders nothing when the field is absent (older API responses)", () => {
    const { container } = mountFooter(undefined);
    // Empty DOM tree under our component root.
    expect(container.firstChild).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 5. Precision/recall band color mapping
// ═══════════════════════════════════════════════════════════════════════

describe("precision/recall band → color mapping", () => {
  function colorFor(precision: number | null): string | null {
    const dq: DetectionQuality = {
      precision,
      recall: 0.5, // independent
      fixture_count: 1, // force state A
      cve_replay_ids: [],
      last_validated_at: null,
    };
    const { container } = mountFooter(dq);
    const chip = container.querySelector<HTMLElement>(".dqf-metric");
    return chip?.style.color ?? null;
  }

  it("≥0.85 maps to --good", () => {
    expect(colorFor(0.95)).toBe("var(--good)");
  });
  it("≥0.70 and <0.85 maps to --moderate", () => {
    expect(colorFor(0.75)).toBe("var(--moderate)");
  });
  it("<0.70 maps to --poor", () => {
    expect(colorFor(0.6)).toBe("var(--poor)");
  });
  it("null maps to muted --text-3 with em-dash value", () => {
    const dq: DetectionQuality = {
      precision: null,
      recall: 0.5,
      fixture_count: 1,
      cve_replay_ids: [],
      last_validated_at: null,
    };
    const { container } = mountFooter(dq);
    const pChip = container.querySelector<HTMLElement>(".dqf-metric");
    expect(pChip?.style.color).toBe("var(--text-3)");
    // Value uses em-dash for null.
    expect(pChip?.textContent).toContain("—");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 6. CVE chip overflow: 5 → 4 visible + "+1 more"
// ═══════════════════════════════════════════════════════════════════════

describe("CVE chip overflow", () => {
  it("renders 4 visible chips and a '+1 more' overflow when 5 ids supplied", () => {
    const cves = [
      "CVE-2025-6514",
      "CVE-2025-6515",
      "CVE-2025-53109",
      "CVE-2025-53110",
      "CVE-2025-53773",
    ];
    const dq: DetectionQuality = {
      precision: 0.9,
      recall: 0.9,
      fixture_count: 0,
      cve_replay_ids: cves,
      last_validated_at: null,
    };
    const { container } = mountFooter(dq);

    expect(container.querySelectorAll(".dqf-cve")).toHaveLength(4);
    const more = container.querySelector<HTMLElement>(".dqf-cve-more");
    expect(more).not.toBeNull();
    expect(more!.textContent).toBe("+1 more");
    // The hidden 5th CVE id appears in the overflow tooltip.
    const title = more!.getAttribute("title") ?? "";
    expect(title).toContain("CVE-2025-53773");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 7. CVE chip href contract
// ═══════════════════════════════════════════════════════════════════════

describe("CVE chip href contract", () => {
  it("opens nvd.nist.gov for the CVE id in a new tab with safe rel", () => {
    const dq: DetectionQuality = {
      precision: 0.9,
      recall: 0.9,
      fixture_count: 0,
      cve_replay_ids: ["CVE-2025-6514"],
      last_validated_at: null,
    };
    const { container } = mountFooter(dq);
    const cve = container.querySelector<HTMLAnchorElement>(".dqf-cve");
    expect(cve).not.toBeNull();
    expect(cve!.getAttribute("href")).toBe(
      "https://nvd.nist.gov/vuln/detail/CVE-2025-6514",
    );
    expect(cve!.getAttribute("target")).toBe("_blank");
    expect(cve!.getAttribute("rel")).toBe("noopener noreferrer");
    expect(cve!.getAttribute("aria-label")).toBe("View CVE-2025-6514 on NVD");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 8. Row click target — OWASP MCP signed PDF
// ═══════════════════════════════════════════════════════════════════════

describe("row click target", () => {
  // The row is a <div> (CVE chips inside need to be <a>; nested anchors are
  // invalid HTML). The trailing .dqf-cta anchor IS the click target. It is
  // present in all three states (A/B/C).
  it("State A: trailing CTA href is the OWASP MCP signed PDF for the slug", () => {
    const dq: DetectionQuality = {
      precision: 0.9,
      recall: 0.9,
      fixture_count: 1,
      cve_replay_ids: [],
      last_validated_at: null,
    };
    const { container } = mountFooter(dq, { slug: "my-server" });
    const cta = container.querySelector<HTMLAnchorElement>(".dqf-cta");
    expect(cta).not.toBeNull();
    expect(cta!.getAttribute("href")).toBe(
      "http://api.example.test/api/v1/servers/my-server/compliance/owasp_mcp.pdf",
    );
    expect(cta!.getAttribute("target")).toBe("_blank");
    expect(cta!.getAttribute("rel")).toBe("noopener noreferrer");
  });

  it("State C: 'not wired' row CTA still links to the OWASP MCP PDF", () => {
    const { container } = mountFooter(null, { slug: "my-server" });
    expect(container.querySelector(".dqf-row-unwired")).not.toBeNull();
    const cta = container.querySelector<HTMLAnchorElement>(".dqf-cta");
    expect(cta).not.toBeNull();
    expect(cta!.getAttribute("href")).toBe(
      "http://api.example.test/api/v1/servers/my-server/compliance/owasp_mcp.pdf",
    );
  });

  it("encodes slug for URL safety", () => {
    const { container } = mountFooter(null, { slug: "edge case/slug" });
    const cta = container.querySelector<HTMLAnchorElement>(".dqf-cta");
    expect(cta!.getAttribute("href")).toContain("edge%20case%2Fslug");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 9. Accessibility — aria-labels everywhere interactive
// ═══════════════════════════════════════════════════════════════════════

describe("accessibility", () => {
  it("State A: row + CTA carry aria-label 'View signed evidence backing for <ruleId>'", () => {
    const dq: DetectionQuality = {
      precision: 0.95,
      recall: 0.88,
      fixture_count: 12,
      cve_replay_ids: ["CVE-2025-6514"],
      last_validated_at: "2026-04-27T12:00:00.000Z",
    };
    const { container } = mountFooter(dq, { ruleId: "K1" });

    const row = container.querySelector(".dqf-row");
    expect(row!.getAttribute("aria-label")).toBe(
      "View signed evidence backing for K1",
    );
    const cta = container.querySelector<HTMLAnchorElement>(".dqf-cta");
    expect(cta!.getAttribute("aria-label")).toBe(
      "View signed evidence backing for K1",
    );

    // Every interactive chip carries an aria-label.
    const cve = container.querySelector<HTMLAnchorElement>(".dqf-cve");
    expect(cve!.getAttribute("aria-label")).toBeTruthy();

    for (const chip of Array.from(
      container.querySelectorAll<HTMLElement>(".dqf-metric"),
    )) {
      expect(chip.getAttribute("aria-label")).toMatch(
        /^(precision|recall) /,
      );
    }
  });

  it("State B + State C row + CTA aria-labels reflect the rule id", () => {
    const dqEmpty: DetectionQuality = {
      precision: null,
      recall: null,
      fixture_count: 0,
      cve_replay_ids: [],
      last_validated_at: null,
    };
    const { container: c1 } = mountFooter(dqEmpty, { ruleId: "L5" });
    expect(
      c1.querySelector(".dqf-row-empty")?.getAttribute("aria-label"),
    ).toBe("View signed evidence backing for L5");
    expect(
      c1.querySelector(".dqf-cta")?.getAttribute("aria-label"),
    ).toBe("View signed evidence backing for L5");

    const { container: c2 } = mountFooter(null, { ruleId: "M2" });
    expect(
      c2.querySelector(".dqf-row-unwired")?.getAttribute("aria-label"),
    ).toBe("View signed evidence backing for M2");
    expect(
      c2.querySelector(".dqf-cta")?.getAttribute("aria-label"),
    ).toBe("View signed evidence backing for M2");
  });
});
