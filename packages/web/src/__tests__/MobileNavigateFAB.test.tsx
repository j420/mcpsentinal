// @vitest-environment jsdom
/**
 * MobileNavigateFAB behavioural tests.
 *
 * Guards:
 *   - FAB starts hidden until the user scrolls past 360px (-visible
 *     class flips on)
 *   - Clicking the FAB opens the bottom-sheet (role=dialog)
 *   - Bottom sheet renders the expected TOC rows for the current lens
 *   - Bottom sheet hides per-category rows in compliance lens
 *   - Esc closes the sheet
 *   - Backdrop click closes; click inside the sheet does NOT
 *   - Tapping a row sets the URL hash and closes the sheet
 *   - Body scroll lock applied + cleared
 */

import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import React from "react";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import MobileNavigateFAB from "@/components/MobileNavigateFAB";
import type { DeepDiveCategory } from "@/lib/deep-dive";

let mockSearchParamsString = "";
vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(mockSearchParamsString),
}));

beforeEach(() => {
  mockSearchParamsString = "";
  document.body.style.overflow = "";
  Object.defineProperty(window, "scrollY", {
    value: 0,
    configurable: true,
    writable: true,
  });
});

afterEach(() => {
  cleanup();
  document.body.style.overflow = "";
});

function emptySev() {
  return { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
}

function makeCategories(): DeepDiveCategory[] {
  return [
    {
      id: "code-vulns",
      title: "Code Vulnerabilities",
      summary: "",
      frameworks: [],
      counts: {
        rules_total: 0,
        rules_passed: 0,
        rules_with_findings: 0,
        rules_skipped: 0,
        finding_count: 0,
        severity_breakdown: emptySev(),
      },
      sub_categories: [],
    },
    {
      id: "prompt-injection",
      title: "Prompt Injection",
      summary: "",
      frameworks: [],
      counts: {
        rules_total: 0,
        rules_passed: 0,
        rules_with_findings: 0,
        rules_skipped: 0,
        finding_count: 0,
        severity_breakdown: emptySev(),
      },
      sub_categories: [],
    },
  ];
}

function renderFab(
  overrides: Partial<React.ComponentProps<typeof MobileNavigateFAB>> = {},
) {
  return render(
    <MobileNavigateFAB
      categories={overrides.categories ?? makeCategories()}
      lens={overrides.lens ?? "story"}
      hasChains={overrides.hasChains ?? true}
      hasSurface={overrides.hasSurface ?? true}
      hasCoverageLedger={overrides.hasCoverageLedger ?? true}
    />,
  );
}

describe("MobileNavigateFAB", () => {
  it("starts hidden (no -visible class) when scrollY is 0", () => {
    renderFab();
    const fab = screen.getByRole("button", { name: /Open page navigation/ });
    expect(fab.classList.contains("mobile-nav-fab-visible")).toBe(false);
  });

  it("becomes visible after the user scrolls past 360px", () => {
    renderFab();
    const fab = screen.getByRole("button", { name: /Open page navigation/ });
    expect(fab.classList.contains("mobile-nav-fab-visible")).toBe(false);
    act(() => {
      Object.defineProperty(window, "scrollY", { value: 400, configurable: true });
      window.dispatchEvent(new Event("scroll"));
    });
    expect(fab.classList.contains("mobile-nav-fab-visible")).toBe(true);
  });

  it("clicking the FAB opens the bottom sheet (role=dialog)", () => {
    renderFab();
    fireEvent.click(
      screen.getByRole("button", { name: /Open page navigation/ }),
    );
    expect(screen.getByRole("dialog")).toBeTruthy();
    expect(screen.getByText("Jump to section")).toBeTruthy();
  });

  it("renders the expected TOC rows in Story lens", () => {
    renderFab({ lens: "story" });
    fireEvent.click(
      screen.getByRole("button", { name: /Open page navigation/ }),
    );
    // Story lens: Verdict + Overview + Attack stories + Capability surface
    // + Coverage ledger + 2 categories + Provenance = 8 rows
    const rows = screen.getAllByRole("button").filter((b) =>
      b.classList.contains("mobile-nav-sheet-link"),
    );
    expect(rows.length).toBe(8);
    expect(rows.map((r) => r.textContent?.trim())).toEqual(
      expect.arrayContaining([
        expect.stringContaining("Verdict"),
        expect.stringContaining("Overview"),
        expect.stringContaining("Attack stories"),
        expect.stringContaining("Capability surface"),
        expect.stringContaining("Coverage ledger"),
        expect.stringContaining("Code Vulnerabilities"),
        expect.stringContaining("Prompt Injection"),
        expect.stringContaining("Provenance"),
      ]),
    );
  });

  it("Compliance lens hides per-category rows and adds a 'Compliance posture' row", () => {
    renderFab({ lens: "compliance" });
    fireEvent.click(
      screen.getByRole("button", { name: /Open page navigation/ }),
    );
    const rows = screen.getAllByRole("button").filter((b) =>
      b.classList.contains("mobile-nav-sheet-link"),
    );
    const labels = rows.map((r) => r.textContent?.trim() ?? "");
    expect(labels.some((l) => l.includes("Compliance posture"))).toBe(true);
    expect(labels.every((l) => !l.includes("Code Vulnerabilities"))).toBe(true);
    expect(labels.every((l) => !l.includes("Attack stories"))).toBe(true);
  });

  it("hides Coverage ledger row when hasCoverageLedger=false", () => {
    renderFab({ hasCoverageLedger: false });
    fireEvent.click(
      screen.getByRole("button", { name: /Open page navigation/ }),
    );
    const rows = screen.getAllByRole("button").filter((b) =>
      b.classList.contains("mobile-nav-sheet-link"),
    );
    const labels = rows.map((r) => r.textContent?.trim() ?? "");
    expect(labels.every((l) => !l.includes("Coverage ledger"))).toBe(true);
  });

  it("Esc closes the sheet", () => {
    renderFab();
    fireEvent.click(
      screen.getByRole("button", { name: /Open page navigation/ }),
    );
    expect(screen.queryByRole("dialog")).toBeTruthy();
    fireEvent.keyDown(window, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("backdrop click closes; click inside the sheet does NOT", () => {
    const { container } = renderFab();
    fireEvent.click(
      screen.getByRole("button", { name: /Open page navigation/ }),
    );
    fireEvent.click(container.querySelector(".mobile-nav-sheet")!);
    expect(screen.queryByRole("dialog")).toBeTruthy();
    fireEvent.click(container.querySelector(".mobile-nav-backdrop")!);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("× close button strips the dialog from the DOM", () => {
    renderFab();
    fireEvent.click(
      screen.getByRole("button", { name: /Open page navigation/ }),
    );
    fireEvent.click(screen.getByLabelText("Close navigation"));
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("locks body scroll while open and releases on close", () => {
    renderFab();
    fireEvent.click(
      screen.getByRole("button", { name: /Open page navigation/ }),
    );
    expect(document.body.style.overflow).toBe("hidden");
    fireEvent.keyDown(window, { key: "Escape" });
    expect(document.body.style.overflow).toBe("");
  });

  it("hides the FAB when ?finding= is present in the URL (drawer-open guard)", () => {
    mockSearchParamsString = "finding=11111111-2222-3333-4444-555555555555";
    renderFab();
    // Bring scroll past threshold so the FAB would normally appear
    act(() => {
      Object.defineProperty(window, "scrollY", { value: 500, configurable: true });
      window.dispatchEvent(new Event("scroll"));
    });
    const fab = screen.getByRole("button", {
      name: /Open page navigation/,
    });
    // -visible class is gated on (scrolled && !drawerOpen).
    expect(fab.classList.contains("mobile-nav-fab-visible")).toBe(false);
  });
});
