// @vitest-environment jsdom
/**
 * LensDensityControls behavioural tests.
 *
 * Guards: pill clicks fire router.replace with the right URL, defaults
 * are dropped from the URL, localStorage is updated on every click,
 * and the active pill carries data-active="true".
 */

import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import React from "react";
import { cleanup, fireEvent, render } from "@testing-library/react";
import LensDensityControls from "../components/LensDensityControls";

// ── Router mocks ──────────────────────────────────────────────────────
let mockSearchParamsString = "";
const mockRouterReplace: Mock = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: vi.fn(),
    replace: mockRouterReplace,
    refresh: vi.fn(),
    prefetch: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
  }),
  usePathname: () => "/servers/demo",
  useSearchParams: () => new URLSearchParams(mockSearchParamsString),
}));

beforeEach(() => {
  mockSearchParamsString = "";
  mockRouterReplace.mockReset();
  if (typeof window !== "undefined") {
    window.localStorage.clear();
  }
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("LensDensityControls", () => {
  it("marks the current lens + density pills as active", () => {
    const { container } = render(
      <LensDensityControls lens="evidence" density="forensic" />,
    );
    const lensActive = container.querySelectorAll(
      '[aria-label="Lens — what story this page tells"] [data-active="true"]',
    );
    const densityActive = container.querySelectorAll(
      '[aria-label="Density — how much detail per rule"] [data-active="true"]',
    );
    expect(lensActive.length).toBe(1);
    expect(densityActive.length).toBe(1);
    expect(lensActive[0]!.textContent).toBe("Evidence");
    expect(densityActive[0]!.textContent).toBe("Forensic");
  });

  it("clicking a non-default lens writes ?lens= to the URL", () => {
    const { getByText } = render(
      <LensDensityControls lens="story" density="briefing" />,
    );
    fireEvent.click(getByText("Audit"));
    expect(mockRouterReplace).toHaveBeenCalledTimes(1);
    const target = mockRouterReplace.mock.calls[0]![0] as string;
    expect(target).toBe("/servers/demo?lens=audit");
  });

  it("clicking the default lens drops ?lens= from the URL", () => {
    mockSearchParamsString = "lens=audit";
    const { getByText } = render(
      <LensDensityControls lens="audit" density="briefing" />,
    );
    fireEvent.click(getByText("Story"));
    const target = mockRouterReplace.mock.calls[0]![0] as string;
    expect(target).toBe("/servers/demo");
  });

  it("clicking a non-default density writes ?view= to the URL", () => {
    const { getByText } = render(
      <LensDensityControls lens="story" density="briefing" />,
    );
    fireEvent.click(getByText("Forensic"));
    const target = mockRouterReplace.mock.calls[0]![0] as string;
    expect(target).toBe("/servers/demo?view=forensic");
  });

  it("clicking the default density drops ?view= from the URL", () => {
    mockSearchParamsString = "view=forensic";
    const { getByText } = render(
      <LensDensityControls lens="story" density="forensic" />,
    );
    fireEvent.click(getByText("Briefing"));
    const target = mockRouterReplace.mock.calls[0]![0] as string;
    expect(target).toBe("/servers/demo");
  });

  it("preserves other query params when toggling", () => {
    mockSearchParamsString = "q=foo&sev=critical";
    const { getByText } = render(
      <LensDensityControls lens="story" density="briefing" />,
    );
    fireEvent.click(getByText("Audit"));
    const target = mockRouterReplace.mock.calls[0]![0] as string;
    expect(target).toContain("lens=audit");
    expect(target).toContain("q=foo");
    expect(target).toContain("sev=critical");
  });

  it("persists the chosen lens + density to localStorage on click", () => {
    const { getByText } = render(
      <LensDensityControls lens="story" density="briefing" />,
    );
    fireEvent.click(getByText("Evidence"));
    expect(window.localStorage.getItem("dd-lens")).toBe("evidence");
    fireEvent.click(getByText("Dossier"));
    expect(window.localStorage.getItem("dd-view")).toBe("dossier");
  });

  it("clicking the same value as current is a no-op (no router call)", () => {
    const { getByText } = render(
      <LensDensityControls lens="story" density="briefing" />,
    );
    fireEvent.click(getByText("Story"));
    fireEvent.click(getByText("Briefing"));
    expect(mockRouterReplace).not.toHaveBeenCalled();
  });

  it("on mount with no URL params + a stored non-default lens, rewrites the URL", () => {
    window.localStorage.setItem("dd-lens", "audit");
    render(<LensDensityControls lens="story" density="briefing" />);
    // The mount effect fires during render -> microtask flush.
    expect(mockRouterReplace).toHaveBeenCalledTimes(1);
    const target = mockRouterReplace.mock.calls[0]![0] as string;
    expect(target).toContain("lens=audit");
  });

  it("on mount with URL params already set, does NOT rewrite from localStorage", () => {
    mockSearchParamsString = "lens=evidence&view=forensic";
    window.localStorage.setItem("dd-lens", "audit");
    window.localStorage.setItem("dd-view", "briefing");
    render(<LensDensityControls lens="evidence" density="forensic" />);
    // URL is the source of truth — localStorage is ignored when the URL
    // already speaks for itself.
    expect(mockRouterReplace).not.toHaveBeenCalled();
  });
});
