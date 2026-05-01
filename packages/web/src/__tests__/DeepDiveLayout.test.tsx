// @vitest-environment jsdom
/**
 * DeepDiveLayout — slot rendering + structural tests.
 *
 * Pure synchronous component, easy to render.
 *
 * What we guard:
 *   1. Renders both slots (sidebar + main) as ReactNode.
 *   2. Uses the documented CSS classnames (`ddl-grid`, `ddl-rail`, `ddl-main`).
 *   3. Defaults to a clamp() sidebar width when `sidebarWidth` is omitted.
 *   4. Honours a custom sidebarWidth.
 *   5. Sets `data-narrow="false"` on the rail so Agent 5's CSS hooks find it.
 *   6. Picks up the optional `ariaLabel`.
 */

import { describe, it, expect } from "vitest";
import React from "react";
import { render } from "@testing-library/react";
import DeepDiveLayout from "../components/DeepDiveLayout";

describe("DeepDiveLayout", () => {
  it("renders both sidebar and main slots", () => {
    const { container } = render(
      <DeepDiveLayout
        sidebar={<div data-testid="sidebar-content">SIDEBAR</div>}
        main={<div data-testid="main-content">MAIN</div>}
      />,
    );
    expect(container.querySelector("[data-testid='sidebar-content']")?.textContent).toBe(
      "SIDEBAR",
    );
    expect(container.querySelector("[data-testid='main-content']")?.textContent).toBe(
      "MAIN",
    );
  });

  it("uses the documented ddl-* CSS classnames", () => {
    const { container } = render(
      <DeepDiveLayout sidebar={<div />} main={<div />} />,
    );
    expect(container.querySelector(".ddl-grid")).not.toBeNull();
    expect(container.querySelector(".ddl-rail")).not.toBeNull();
    expect(container.querySelector(".ddl-main")).not.toBeNull();
  });

  it("sets data-narrow='false' on the rail by default", () => {
    const { container } = render(
      <DeepDiveLayout sidebar={<span />} main={<span />} />,
    );
    const rail = container.querySelector(".ddl-rail");
    expect(rail).not.toBeNull();
    expect(rail!.getAttribute("data-narrow")).toBe("false");
  });

  it("defaults the sidebar width to a clamp() expression", () => {
    const { container } = render(
      <DeepDiveLayout sidebar={<span />} main={<span />} />,
    );
    const grid = container.querySelector(".ddl-grid") as HTMLElement | null;
    expect(grid).not.toBeNull();
    const inline = grid!.style.getPropertyValue("--ddl-sidebar-w");
    // We just need the default to start with `clamp(` — exact value is in
    // the component default and is intentionally fluid.
    expect(inline.trim().startsWith("clamp(")).toBe(true);
  });

  it("honours a custom sidebarWidth", () => {
    const { container } = render(
      <DeepDiveLayout sidebar={<span />} main={<span />} sidebarWidth="280px" />,
    );
    const grid = container.querySelector(".ddl-grid") as HTMLElement | null;
    expect(grid!.style.getPropertyValue("--ddl-sidebar-w").trim()).toBe("280px");
  });

  it("uses the default ariaLabel 'Deep dive' when omitted", () => {
    const { container } = render(
      <DeepDiveLayout sidebar={<span />} main={<span />} />,
    );
    expect(container.querySelector(".ddl-grid")?.getAttribute("aria-label")).toBe(
      "Deep dive",
    );
  });

  it("honours a custom ariaLabel", () => {
    const { container } = render(
      <DeepDiveLayout
        sidebar={<span />}
        main={<span />}
        ariaLabel="Custom dive label"
      />,
    );
    expect(container.querySelector(".ddl-grid")?.getAttribute("aria-label")).toBe(
      "Custom dive label",
    );
  });

  it("renders the sidebar inside an <aside> for outline correctness", () => {
    const { container } = render(
      <DeepDiveLayout sidebar={<span data-testid="rail-content" />} main={<span />} />,
    );
    const aside = container.querySelector("aside.ddl-rail");
    expect(aside).not.toBeNull();
    expect(aside!.querySelector("[data-testid='rail-content']")).not.toBeNull();
  });

  it("renders the main column with role=region", () => {
    const { container } = render(
      <DeepDiveLayout sidebar={<span />} main={<span data-testid="main-content" />} />,
    );
    const main = container.querySelector(".ddl-main") as HTMLElement | null;
    expect(main!.getAttribute("role")).toBe("region");
  });
});
