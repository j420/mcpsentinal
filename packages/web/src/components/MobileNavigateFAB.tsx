"use client";
/**
 * MobileNavigateFAB — floating "navigate" pill + bottom-sheet TOC.
 *
 * On mobile the existing left-rail sidebar collapses into a `<details>`
 * accordion at the top of the page; once the user scrolls past it,
 * there's no quick way to jump between sections. This component fills
 * that gap with a fixed-position FAB that opens a bottom-sheet TOC
 * pinned to the bottom of the viewport.
 *
 * The TOC is built from the deep-dive payload + a fixed list of major
 * page sections (verdict / hero / chains / surface / coverage /
 * compliance / categories... / provenance). Tap any row → smooth-scroll
 * to that section's `id` and close the sheet.
 *
 * Visibility:
 *   - Hidden above 720px (desktop has the sticky verdict bar + sticky
 *     left-rail sidebar already).
 *   - Hidden when the user is at the top of the page (scroll < 360px) —
 *     the verdict bar is still in view, no need to navigate yet.
 *   - Hidden when the Forensic drawer is open (`?finding=` in URL) so
 *     the FAB doesn't conflict with the drawer's close affordance.
 *
 * Accessibility:
 *   - role="dialog" + aria-modal on the bottom sheet
 *   - aria-expanded on the FAB
 *   - Esc to close + backdrop-click to close
 *   - Initial focus on the close button when the sheet opens
 *   - Returns focus to the FAB on close
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import type { DeepDiveCategory } from "@/lib/deep-dive";

interface MobileNavigateFABProps {
  /** Top-level categories from the deep-dive payload — drives the
   *  per-category jump rows in the bottom sheet. */
  categories: ReadonlyArray<DeepDiveCategory>;
  /** Whether the page is in compliance lens — when true, the per-
   *  category rows hide (the categories aren't rendered) and a single
   *  "Compliance posture" row appears. */
  lens: "story" | "evidence" | "compliance" | "audit";
  /** Whether kill chains / capability surface / coverage ledger are
   *  rendered — drives whether their rows appear in the TOC. */
  hasChains: boolean;
  hasSurface: boolean;
  hasCoverageLedger: boolean;
}

interface TocRow {
  /** Anchor target — element id (the page sets these on each section). */
  href: string;
  label: string;
}

/** Build the TOC row list from the page's current data + lens. */
function buildToc(input: {
  categories: ReadonlyArray<DeepDiveCategory>;
  lens: MobileNavigateFABProps["lens"];
  hasChains: boolean;
  hasSurface: boolean;
  hasCoverageLedger: boolean;
}): TocRow[] {
  const rows: TocRow[] = [];
  rows.push({ href: "#dd-section-verdict", label: "Verdict" });
  rows.push({ href: "#dd-section-hero", label: "Overview" });

  if (input.lens !== "compliance") {
    if (input.hasChains) {
      rows.push({ href: "#dd-section-chains", label: "Attack stories" });
    }
    if (input.hasSurface) {
      rows.push({ href: "#dd-section-surface", label: "Capability surface" });
    }
    if (input.hasCoverageLedger) {
      rows.push({ href: "#dd-section-coverage", label: "Coverage ledger" });
    }
  }

  if (input.lens === "compliance") {
    rows.push({ href: "#dd-section-compliance", label: "Compliance posture" });
  } else {
    // Per-category jumps — uses the existing `id="cat-<id>"` anchor on
    // CategorySection (predates this component).
    for (const cat of input.categories ?? []) {
      if (!cat || !cat.id) continue;
      const label = cat.title ?? cat.id;
      rows.push({ href: `#cat-${cat.id}`, label });
    }
  }

  rows.push({ href: "#dd-section-provenance", label: "Provenance" });
  return rows;
}

export default function MobileNavigateFAB({
  categories,
  lens,
  hasChains,
  hasSurface,
  hasCoverageLedger,
}: MobileNavigateFABProps) {
  const searchParams = useSearchParams();
  const drawerOpen = searchParams.has("finding");

  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const closeBtnRef = useRef<HTMLButtonElement>(null);
  const fabRef = useRef<HTMLButtonElement>(null);

  // Show the FAB only after the user has scrolled past ~360px so the
  // verdict bar is no longer in view. Pure scroll-listener; React
  // already batches setState calls and a 360-vs-not boolean only
  // toggles twice per page-life so the perf overhead is irrelevant.
  useEffect(() => {
    if (typeof window === "undefined") return;
    function onScroll(): void {
      setScrolled(window.scrollY > 360);
    }
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      window.removeEventListener("scroll", onScroll);
    };
  }, []);

  // Close on Esc.
  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent): void {
      if (e.key === "Escape") setOpen(false);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  // Body scroll lock while sheet is open.
  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
    };
  }, [open]);

  // Initial focus on the close button when the sheet opens.
  useEffect(() => {
    if (open && closeBtnRef.current) closeBtnRef.current.focus();
  }, [open]);

  // Restore focus to the FAB when the sheet closes.
  const onSheetClose = useCallback(() => {
    setOpen(false);
    // Defer the focus restore so the FAB exists in the DOM before we
    // try to focus it (the FAB itself may be hidden by `scrolled` —
    // we re-focus the document body in that case).
    setTimeout(() => fabRef.current?.focus(), 0);
  }, []);

  const toc = useMemo(
    () => buildToc({ categories, lens, hasChains, hasSurface, hasCoverageLedger }),
    [categories, lens, hasChains, hasSurface, hasCoverageLedger],
  );

  const onRowClick = useCallback((href: string) => {
    // Use anchor navigation directly — the browser handles smooth
    // scroll via `scroll-margin-top` set on each section by globals.css.
    setOpen(false);
    // Defer the hash change so the sheet's exit animation can start.
    requestAnimationFrame(() => {
      window.location.hash = href;
    });
  }, []);

  const showFab = scrolled && !drawerOpen;

  return (
    <>
      <button
        ref={fabRef}
        type="button"
        className={`mobile-nav-fab${showFab ? " mobile-nav-fab-visible" : ""}`}
        aria-label="Open page navigation"
        aria-expanded={open}
        aria-controls="mobile-nav-sheet"
        onClick={() => setOpen(true)}
      >
        <span aria-hidden="true">≡</span>
        Navigate
      </button>

      {open && (
        <div
          className="mobile-nav-backdrop"
          onClick={onSheetClose}
          role="presentation"
        >
          <div
            id="mobile-nav-sheet"
            className="mobile-nav-sheet"
            role="dialog"
            aria-modal="true"
            aria-labelledby="mobile-nav-sheet-title"
            onClick={(e) => e.stopPropagation()}
          >
            <header className="mobile-nav-sheet-head">
              <h2
                id="mobile-nav-sheet-title"
                className="mobile-nav-sheet-title"
              >
                Jump to section
              </h2>
              <button
                ref={closeBtnRef}
                type="button"
                className="mobile-nav-sheet-close"
                onClick={onSheetClose}
                aria-label="Close navigation"
              >
                ×
              </button>
            </header>
            <ul className="mobile-nav-sheet-list">
              {toc.map((row) => (
                <li key={row.href} className="mobile-nav-sheet-item">
                  <button
                    type="button"
                    className="mobile-nav-sheet-link"
                    onClick={() => onRowClick(row.href)}
                  >
                    {row.label}
                    <span
                      className="mobile-nav-sheet-chev"
                      aria-hidden="true"
                    >
                      ↗
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </>
  );
}
