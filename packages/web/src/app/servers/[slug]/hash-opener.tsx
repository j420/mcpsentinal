"use client";

/**
 * HashOpener — auto-opens every `<details>` ancestor of the URL-hash
 * target, then scrolls the target into view.
 *
 * The page wraps each category in a `<details>` that's open by default
 * only when the category has findings. Clicking a TOC link to a
 * clean / collapsed category would otherwise scroll the user to a row
 * that's still closed. This tiny client island fixes that:
 *   - on mount (initial hash)
 *   - on every `hashchange`
 *   - walks the target's ancestor chain and sets `open=true` on every
 *     `<details>` found.
 *
 * No state, no markup. ~30 LOC of client JS — the only client work on
 * the page besides the copy-scan-id button.
 */

import { useEffect } from "react";

export default function HashOpener(): null {
  useEffect(() => {
    function openHashTarget(): void {
      const hash = window.location.hash;
      if (!hash || hash === "#") return;
      let target: Element | null = null;
      try {
        target = document.querySelector(hash);
      } catch {
        // Invalid selector — bail.
        return;
      }
      if (!target) return;
      let node: Element | null = target;
      while (node) {
        if (node.tagName === "DETAILS") {
          (node as HTMLDetailsElement).open = true;
        }
        node = node.parentElement;
      }
      // Re-scroll once the details have expanded.
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    openHashTarget();
    window.addEventListener("hashchange", openHashTarget);
    return () => window.removeEventListener("hashchange", openHashTarget);
  }, []);
  return null;
}
