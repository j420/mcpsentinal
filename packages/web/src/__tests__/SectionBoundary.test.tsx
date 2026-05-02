// @vitest-environment jsdom
/**
 * SectionBoundary smoke tests.
 *
 * Guards: a throwing child renders the fallback (not the children),
 * the section name lands in a hidden data attribute, and a normal
 * child renders unchanged.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { cleanup, render } from "@testing-library/react";
import SectionBoundary from "../components/SectionBoundary";

afterEach(() => cleanup());

function Boom({ msg }: { msg: string }): React.ReactElement {
  throw new Error(msg);
}

describe("SectionBoundary", () => {
  it("renders children unchanged when nothing throws", () => {
    const { getByText, container } = render(
      <SectionBoundary section="x">
        <p>hello</p>
      </SectionBoundary>,
    );
    expect(getByText("hello")).toBeTruthy();
    expect(
      container.querySelector(".section-boundary-fallback"),
    ).toBeNull();
  });

  it("catches a child render exception and renders the fallback", () => {
    // Suppress React's noisy console.error for the throw — class
    // boundaries log automatically.
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const { container } = render(
      <SectionBoundary section="hero" label="Hero">
        <Boom msg="probe-error-msg" />
      </SectionBoundary>,
    );
    const fallback = container.querySelector(".section-boundary-fallback");
    expect(fallback).not.toBeNull();
    expect(fallback!.getAttribute("data-section-error")).toBe("hero");
    expect(fallback!.getAttribute("data-section-error-msg")).toBe(
      "probe-error-msg",
    );
    spy.mockRestore();
  });

  it("uses the section name as the visible label when none provided", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const { container } = render(
      <SectionBoundary section="my-block">
        <Boom msg="x" />
      </SectionBoundary>,
    );
    expect(container.textContent).toContain("my-block");
    spy.mockRestore();
  });
});
