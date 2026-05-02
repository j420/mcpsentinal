// @vitest-environment jsdom
/**
 * HoverTraceController behavioural tests.
 *
 * Guards:
 *   - Mounting attaches mouseover/mouseout listeners on document.body.
 *   - Hovering on a [data-trace="x"] element sets body[data-trace-active="x"]
 *     and stamps data-trace-match on every other [data-trace="x"] element.
 *   - Mousing out clears the active state and all match attributes.
 *   - Mousing between two siblings that share the same trace key does NOT
 *     flicker (active state stays).
 *   - Hovering an element with NO data-trace ancestor is a no-op.
 *   - Unmount removes the listeners + clears any active state.
 *   - Keyboard focus on a [data-trace] element activates the same wiring.
 */

import { afterEach, describe, expect, it } from "vitest";
import React from "react";
import { cleanup, fireEvent, render } from "@testing-library/react";
import HoverTraceController from "../components/HoverTraceController";

afterEach(() => {
  cleanup();
  // Defensive: clear any leaked attributes between tests.
  document.body.removeAttribute("data-trace-active");
  document
    .querySelectorAll("[data-trace-match]")
    .forEach((el) => el.removeAttribute("data-trace-match"));
});

function Page() {
  return (
    <>
      <HoverTraceController />
      <div>
        <span data-trace="tool:fetch_url" data-testid="fetch1">
          fetch_url (1)
        </span>
        <span data-trace="tool:fetch_url" data-testid="fetch2">
          fetch_url (2)
        </span>
        <span data-trace="tool:read_file" data-testid="read1">
          read_file
        </span>
        <span data-testid="no-trace">no trace key here</span>
      </div>
    </>
  );
}

describe("HoverTraceController", () => {
  it("hovering a [data-trace] element marks every same-key element + sets body attr", () => {
    const { getByTestId } = render(<Page />);
    fireEvent.mouseOver(getByTestId("fetch1"));
    expect(document.body.getAttribute("data-trace-active")).toBe(
      "tool:fetch_url",
    );
    expect(getByTestId("fetch1").getAttribute("data-trace-match")).toBe("true");
    expect(getByTestId("fetch2").getAttribute("data-trace-match")).toBe("true");
    expect(getByTestId("read1").getAttribute("data-trace-match")).toBeNull();
  });

  it("mouseout clears the active state and all match attributes", () => {
    const { getByTestId } = render(<Page />);
    fireEvent.mouseOver(getByTestId("fetch1"));
    fireEvent.mouseOut(getByTestId("fetch1"), {
      relatedTarget: getByTestId("no-trace"),
    });
    expect(document.body.getAttribute("data-trace-active")).toBeNull();
    expect(getByTestId("fetch1").getAttribute("data-trace-match")).toBeNull();
    expect(getByTestId("fetch2").getAttribute("data-trace-match")).toBeNull();
  });

  it("moving between two same-key elements keeps the active state (no flicker)", () => {
    const { getByTestId } = render(<Page />);
    fireEvent.mouseOver(getByTestId("fetch1"));
    expect(document.body.getAttribute("data-trace-active")).toBe(
      "tool:fetch_url",
    );
    // mouseOut from fetch1 with relatedTarget=fetch2 — same key, no clear.
    fireEvent.mouseOut(getByTestId("fetch1"), {
      relatedTarget: getByTestId("fetch2"),
    });
    expect(document.body.getAttribute("data-trace-active")).toBe(
      "tool:fetch_url",
    );
    expect(getByTestId("fetch2").getAttribute("data-trace-match")).toBe("true");
  });

  it("switching to a different trace key clears prior matches", () => {
    const { getByTestId } = render(<Page />);
    fireEvent.mouseOver(getByTestId("fetch1"));
    fireEvent.mouseOver(getByTestId("read1"));
    expect(document.body.getAttribute("data-trace-active")).toBe(
      "tool:read_file",
    );
    expect(getByTestId("read1").getAttribute("data-trace-match")).toBe("true");
    expect(getByTestId("fetch1").getAttribute("data-trace-match")).toBeNull();
    expect(getByTestId("fetch2").getAttribute("data-trace-match")).toBeNull();
  });

  it("hovering an element with no data-trace ancestor is a no-op", () => {
    const { getByTestId } = render(<Page />);
    fireEvent.mouseOver(getByTestId("no-trace"));
    expect(document.body.getAttribute("data-trace-active")).toBeNull();
  });

  it("focusin on a [data-trace] element activates the same wiring (keyboard parity)", () => {
    const { getByTestId } = render(<Page />);
    // jsdom dispatches focusin via fireEvent.focus on the element itself.
    fireEvent.focus(getByTestId("fetch1"));
    expect(document.body.getAttribute("data-trace-active")).toBe(
      "tool:fetch_url",
    );
    expect(getByTestId("fetch2").getAttribute("data-trace-match")).toBe("true");
  });

  it("unmounting clears active state + all match attributes", () => {
    const { getByTestId, unmount } = render(<Page />);
    fireEvent.mouseOver(getByTestId("fetch1"));
    expect(document.body.getAttribute("data-trace-active")).toBe(
      "tool:fetch_url",
    );
    unmount();
    expect(document.body.getAttribute("data-trace-active")).toBeNull();
    // Note: the elements themselves are gone after unmount — there's
    // nothing to query for data-trace-match. The clean-state assertion
    // is on the body attribute.
  });

  it("idempotent when the same key is re-activated", () => {
    const { getByTestId } = render(<Page />);
    fireEvent.mouseOver(getByTestId("fetch1"));
    const beforeMatches = document.querySelectorAll("[data-trace-match]").length;
    fireEvent.mouseOver(getByTestId("fetch2"));
    const afterMatches = document.querySelectorAll("[data-trace-match]").length;
    expect(afterMatches).toBe(beforeMatches);
    expect(document.body.getAttribute("data-trace-active")).toBe(
      "tool:fetch_url",
    );
  });
});
