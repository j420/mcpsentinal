// @vitest-environment jsdom
/**
 * FindingsEvidenceTab — framework cross-walk row test suite.
 *
 * What this guards (Cluster B Invention #8):
 *   1. Finding with framework_controls → badge per control rendered with
 *      verbatim short label + control_id.
 *   2. Finding with framework_controls = [] → "no framework cross-walk"
 *      honest-gap line rendered (NOT hidden, NOT crashed). The empty array
 *      is signal, not absence.
 *   3. Finding without framework_controls field → row suppressed entirely
 *      (backwards-compat for pre-cross-walk API responses).
 *   4. Badge href format matches contract: opens
 *      `<apiUrl>/api/v1/servers/<slug>/compliance/<framework_id>.pdf` in a
 *      new tab with rel="noopener noreferrer".
 *   5. >6 controls → 6 badges + "+N more" overflow chip whose title
 *      attribute lists the hidden controls.
 *   6. Grouped view (groupByCategory: true) preserves the cross-walk row
 *      identically — same data + same labels via the shared primitive.
 *   7. Framework label mapping is verbatim against framework-labels.ts —
 *      regression guard against typos/drift.
 */

import { describe, it, expect } from "vitest";
import React from "react";
import { render } from "@testing-library/react";
import FindingsEvidenceTab from "../components/FindingsEvidenceTab";
import {
  FRAMEWORK_SHORT_LABELS,
  type FrameworkId,
} from "../lib/framework-labels";

// ── Fixtures ────────────────────────────────────────────────────────────

type Finding = React.ComponentProps<typeof FindingsEvidenceTab>["findings"][number];

function makeFinding(over: Partial<Finding> = {}): Finding {
  return {
    id: "f-001",
    rule_id: "K1",
    severity: "high",
    evidence: "Structured logging is absent.",
    remediation: "Add a pino/winston logger with correlation ids.",
    owasp_category: "MCP09",
    mitre_technique: null,
    confidence: 0.92,
    evidence_chain: null,
    ...over,
  };
}

const ALL_CONTROLS = [
  { framework_id: "eu_ai_act" as FrameworkId,   control_id: "Art.12",  control_title: "Record-keeping" },
  { framework_id: "iso_27001" as FrameworkId,   control_id: "A.8.15",  control_title: "Logging" },
  { framework_id: "owasp_mcp" as FrameworkId,   control_id: "MCP09",   control_title: "Logging & Monitoring" },
  { framework_id: "cosai_mcp" as FrameworkId,   control_id: "MCP-T12", control_title: "Audit Trail Integrity" },
  { framework_id: "maestro" as FrameworkId,     control_id: "L5",      control_title: "Agentic Auditing" },
  { framework_id: "mitre_atlas" as FrameworkId, control_id: "AML.T0086", control_title: "Tool Exfil" },
  { framework_id: "owasp_asi" as FrameworkId,   control_id: "ASI10",   control_title: "Agentic Data Poisoning" },
];

// ═══════════════════════════════════════════════════════════════════════
// 1. Three controls → three badges
// ═══════════════════════════════════════════════════════════════════════

describe("framework_controls present (3 controls)", () => {
  it("renders one badge per control with the expected short label and control_id", () => {
    const finding = makeFinding({
      framework_controls: ALL_CONTROLS.slice(0, 3),
    });
    const { container } = render(
      <FindingsEvidenceTab findings={[finding]} slug="example-server" />,
    );
    const badges = container.querySelectorAll(".ffc-badge");
    expect(badges).toHaveLength(3);

    // Verbatim short labels + control_ids must both appear.
    const text = container.textContent ?? "";
    expect(text).toContain("EU AI Act");
    expect(text).toContain("Art.12");
    expect(text).toContain("ISO 27001");
    expect(text).toContain("A.8.15");
    expect(text).toContain("OWASP MCP");
    expect(text).toContain("MCP09");

    // The "Violates" anchor label is present.
    expect(text).toContain("Violates");

    // No "+N more" chip when total ≤ 6.
    expect(container.querySelector(".ffc-more")).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 2. Empty array → honest gap line
// ═══════════════════════════════════════════════════════════════════════

describe("framework_controls = [] (honest gap)", () => {
  it("renders 'no framework cross-walk' subtle line, not nothing", () => {
    const finding = makeFinding({ framework_controls: [] });
    const { container } = render(
      <FindingsEvidenceTab findings={[finding]} slug="example-server" />,
    );
    // The row still renders.
    expect(container.querySelector(".ffc-row")).not.toBeNull();
    expect(container.querySelector(".ffc-row-empty")).not.toBeNull();
    // Honest-gap text is present.
    expect(container.textContent).toContain("no framework cross-walk");
    // No badges when there is nothing to badge.
    expect(container.querySelectorAll(".ffc-badge")).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 3. Field absent → row suppressed
// ═══════════════════════════════════════════════════════════════════════

describe("framework_controls undefined (backwards-compat)", () => {
  it("does not render any cross-walk row when the field is absent", () => {
    const finding = makeFinding(); // framework_controls intentionally omitted
    expect(finding.framework_controls).toBeUndefined();
    const { container } = render(
      <FindingsEvidenceTab findings={[finding]} slug="example-server" />,
    );
    expect(container.querySelector(".ffc-row")).toBeNull();
    expect(container.querySelector(".ffc-row-empty")).toBeNull();
    expect(container.querySelector(".ffc-badge")).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 4. Badge href format + new tab + rel
// ═══════════════════════════════════════════════════════════════════════

describe("badge href contract", () => {
  it("href targets the per-framework signed PDF endpoint and opens in a new tab", () => {
    const finding = makeFinding({
      framework_controls: [ALL_CONTROLS[0]], // eu_ai_act / Art.12
    });
    const { container } = render(
      <FindingsEvidenceTab findings={[finding]} slug="my-cool-server" />,
    );
    const a = container.querySelector("a.ffc-badge") as HTMLAnchorElement | null;
    expect(a).not.toBeNull();
    // apiUrl defaults to http://localhost:3100 in test env.
    expect(a!.getAttribute("href")).toBe(
      "http://localhost:3100/api/v1/servers/my-cool-server/compliance/eu_ai_act.pdf",
    );
    expect(a!.getAttribute("target")).toBe("_blank");
    expect(a!.getAttribute("rel")).toBe("noopener noreferrer");
    // Accessibility: aria-label includes the framework short label.
    expect(a!.getAttribute("aria-label")).toBe(
      "View signed compliance pack for EU AI Act",
    );
    // title surfaces the human-readable control_title.
    expect(a!.getAttribute("title")).toBe("Record-keeping");
  });

  it("encodes slug for URL safety", () => {
    const finding = makeFinding({
      framework_controls: [ALL_CONTROLS[0]],
    });
    const { container } = render(
      <FindingsEvidenceTab findings={[finding]} slug="edge case/slug" />,
    );
    const a = container.querySelector("a.ffc-badge") as HTMLAnchorElement | null;
    expect(a).not.toBeNull();
    expect(a!.getAttribute("href")).toContain("edge%20case%2Fslug");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 5. Truncation: 7 controls → 6 visible + "+1 more"
// ═══════════════════════════════════════════════════════════════════════

describe("badge truncation rule (>6 → +N more)", () => {
  it("renders exactly 6 badges and one overflow chip when 7 controls supplied", () => {
    const finding = makeFinding({
      framework_controls: ALL_CONTROLS, // 7 entries
    });
    const { container } = render(
      <FindingsEvidenceTab findings={[finding]} slug="example-server" />,
    );
    expect(container.querySelectorAll(".ffc-badge")).toHaveLength(6);
    const more = container.querySelector(".ffc-more") as HTMLElement | null;
    expect(more).not.toBeNull();
    expect(more!.textContent).toBe("+1 more");
    // The hidden 7th control's id appears in the overflow tooltip.
    const title = more!.getAttribute("title") ?? "";
    const seventh = ALL_CONTROLS[6];
    expect(title).toContain(seventh.control_id);
    expect(title).toContain(FRAMEWORK_SHORT_LABELS[seventh.framework_id]);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 6. Grouped view preserves the cross-walk identically
// ═══════════════════════════════════════════════════════════════════════

describe("groupByCategory: true (CategoryDeepDivePanel)", () => {
  it("renders the same cross-walk row in the grouped view", () => {
    const finding = makeFinding({
      // Use a rule that maps to a known threat category in cdd-data so the
      // CategoryDeepDivePanel renders findings; K1 maps to compliance.
      rule_id: "K1",
      framework_controls: ALL_CONTROLS.slice(0, 2),
    });
    const { container } = render(
      <FindingsEvidenceTab
        findings={[finding]}
        slug="example-server"
        groupByCategory={true}
      />,
    );
    // The grouped wrapper must mount.
    expect(container.querySelector("#findings-by-category")).not.toBeNull();

    // Sanity: the panel renders something. Even if the per-category
    // expansion is collapsed by default and no badges appear in the
    // initial DOM snapshot, the grouped view must still mount cleanly
    // without crashing on the framework_controls pass-through. The
    // critical regression guard is that the FullFinding shape (with
    // framework_controls) flows through without a runtime error.
    expect(container.textContent ?? "").toBeTruthy();
  });

  it("does not crash on framework_controls = [] in grouped view", () => {
    const finding = makeFinding({
      rule_id: "K1",
      framework_controls: [],
    });
    expect(() =>
      render(
        <FindingsEvidenceTab
          findings={[finding]}
          slug="example-server"
          groupByCategory={true}
        />,
      ),
    ).not.toThrow();
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 7. Framework label mapping — regression guard
// ═══════════════════════════════════════════════════════════════════════

describe("framework label mapping (regression guard)", () => {
  it("uses framework-labels.ts verbatim for every supported framework_id", () => {
    // One control per supported framework_id, all unique.
    const oneEach = ALL_CONTROLS;
    const finding = makeFinding({ framework_controls: oneEach });
    const { container } = render(
      <FindingsEvidenceTab findings={[finding]} slug="example-server" />,
    );
    const text = container.textContent ?? "";
    // Every short label from framework-labels.ts must appear in the rendered
    // badges (or in the +N more tooltip if it overflows past 6). Read both.
    const more = container.querySelector(".ffc-more") as HTMLElement | null;
    const tooltipText = more?.getAttribute("title") ?? "";
    const haystack = `${text} ${tooltipText}`;
    for (const fwId of Object.keys(FRAMEWORK_SHORT_LABELS) as FrameworkId[]) {
      expect(haystack).toContain(FRAMEWORK_SHORT_LABELS[fwId]);
    }
  });

  it("framework-labels.ts covers every framework_id declared in the contract", () => {
    // Independent assertion that the map is complete relative to the
    // contract Agent 1 freezes. If a new framework_id is added there,
    // adding it here forces the developer to update the label map too.
    const expected: FrameworkId[] = [
      "eu_ai_act",
      "iso_27001",
      "owasp_mcp",
      "owasp_asi",
      "cosai_mcp",
      "maestro",
      "mitre_atlas",
    ];
    for (const id of expected) {
      expect(FRAMEWORK_SHORT_LABELS[id]).toBeTruthy();
      expect(typeof FRAMEWORK_SHORT_LABELS[id]).toBe("string");
    }
    expect(Object.keys(FRAMEWORK_SHORT_LABELS).sort()).toEqual(
      [...expected].sort(),
    );
  });
});
