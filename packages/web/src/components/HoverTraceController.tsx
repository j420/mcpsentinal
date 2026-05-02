"use client";
/**
 * HoverTraceController — page-wide "spatial reasoning" interaction layer.
 *
 * The Deep Dive page contains repeated references to the same entities
 * (a tool name appears in capability surface, kill-chain steps, evidence
 * chains; a rule id appears in coverage ledger AND in the taxonomy stack;
 * a CVE id appears on multiple rules). This controller turns those
 * repetitions into a connected map: hover any element with `data-trace`,
 * every other element with the same `data-trace` value lights up.
 *
 * Mechanics:
 *   - Single delegated mouseover/mouseout listener on document.body.
 *   - On hover of a `[data-trace="<key>"]` element, query every other
 *     element with the same value and stamp `data-trace-match="true"`,
 *     then set `data-trace-active="<key>"` on document.body.
 *   - On mouseout (when no related target shares the trace key), clear
 *     all matches + the body attribute.
 *
 * CSS handles the visual layer (defined in globals.css under "Hover-
 * to-Trace"). The controller emits no markup of its own.
 *
 * Why mouse events (not :has() / sibling selectors): CSS-only matching
 * across the entire DOM tree requires `:has()` with attribute equality
 * (e.g. `body:has([data-trace="x"]:hover) [data-trace="x"]`). That's
 * supported in modern browsers but doesn't degrade well, and forces a
 * separate rule per literal trace key. JS gives us one rule + arbitrary
 * keys + future-proof to multi-key elements.
 *
 * Touch / keyboard parity: pointer events fire on touch devices via
 * synthesised mouseover. For keyboard users we also fire on focusin /
 * focusout so a Tab-through navigator gets the same connections.
 *
 * Mounts once at the page root. Server-rendered as `null` (no markup).
 */

import { useEffect } from "react";

const ACTIVE_ATTR = "data-trace-active";
const MATCH_ATTR = "data-trace-match";

function escapeAttrValue(value: string): string {
  // CSS.escape isn't available in every environment (SSR, jsdom in some
  // configs). Fall back to a manual escape for the characters that can
  // appear inside our trace keys (alphanum + ":" + "-" + "_" + ".").
  if (typeof CSS !== "undefined" && typeof CSS.escape === "function") {
    return CSS.escape(value);
  }
  return value.replace(/(["\\])/g, "\\$1");
}

export default function HoverTraceController() {
  useEffect(() => {
    if (typeof document === "undefined") return;

    let activeKey: string | null = null;

    function clearMatches() {
      const matched = document.querySelectorAll(`[${MATCH_ATTR}]`);
      matched.forEach((el) => el.removeAttribute(MATCH_ATTR));
      document.body.removeAttribute(ACTIVE_ATTR);
      activeKey = null;
    }

    function activate(target: Element) {
      const key = target.getAttribute("data-trace");
      if (!key) return;
      if (key === activeKey) return; // already active — skip churn
      // Clear previous before stamping new matches so we don't leak.
      const prev = document.querySelectorAll(`[${MATCH_ATTR}]`);
      prev.forEach((el) => el.removeAttribute(MATCH_ATTR));
      // Match every element with the same data-trace value.
      const sel = `[data-trace="${escapeAttrValue(key)}"]`;
      let matched: NodeListOf<Element>;
      try {
        matched = document.querySelectorAll(sel);
      } catch {
        // Defensive: if the key contains characters that escape
        // incorrectly we silently bail out — no highlight is better
        // than a thrown selector.
        return;
      }
      matched.forEach((el) => el.setAttribute(MATCH_ATTR, "true"));
      document.body.setAttribute(ACTIVE_ATTR, key);
      activeKey = key;
    }

    function findTraceTarget(node: EventTarget | null): Element | null {
      if (!(node instanceof Element)) return null;
      return node.closest("[data-trace]");
    }

    function onMouseOver(e: MouseEvent): void {
      const target = findTraceTarget(e.target);
      if (target) activate(target);
    }

    function onMouseOut(e: MouseEvent): void {
      const target = findTraceTarget(e.target);
      if (!target) return;
      const related = findTraceTarget(e.relatedTarget);
      // Only clear when the mouse leaves the trace cluster entirely —
      // moving between sibling elements that share the same key keeps
      // the highlight on (no flicker).
      if (
        related &&
        related.getAttribute("data-trace") === target.getAttribute("data-trace")
      ) {
        return;
      }
      clearMatches();
    }

    function onFocusIn(e: FocusEvent): void {
      const target = findTraceTarget(e.target);
      if (target) activate(target);
    }

    function onFocusOut(e: FocusEvent): void {
      const target = findTraceTarget(e.target);
      if (!target) return;
      const related = findTraceTarget(e.relatedTarget);
      if (
        related &&
        related.getAttribute("data-trace") === target.getAttribute("data-trace")
      ) {
        return;
      }
      clearMatches();
    }

    document.body.addEventListener("mouseover", onMouseOver);
    document.body.addEventListener("mouseout", onMouseOut);
    document.body.addEventListener("focusin", onFocusIn);
    document.body.addEventListener("focusout", onFocusOut);

    return () => {
      document.body.removeEventListener("mouseover", onMouseOver);
      document.body.removeEventListener("mouseout", onMouseOut);
      document.body.removeEventListener("focusin", onFocusIn);
      document.body.removeEventListener("focusout", onFocusOut);
      clearMatches();
    };
  }, []);

  return null;
}
