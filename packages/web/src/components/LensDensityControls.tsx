"use client";
/**
 * LensDensityControls — twin pill-row toggle that drives the Deep Dive
 * page's `data-lens` and `data-density` attributes via the URL.
 *
 * Why client + URL state + localStorage:
 *   - Client component: pill clicks need an event handler; useRouter +
 *     useSearchParams are client hooks. The controls are small and pure
 *     so the client-bundle cost is minimal.
 *   - URL state (?lens=, ?view=): shareable links land on the same view
 *     the sender was reading. SSR reads the same params so first paint
 *     matches without a hydration flash.
 *   - localStorage persistence: a returning visitor lands on their last
 *     chosen view across sessions, EVEN when the URL omits ?lens / ?view.
 *     A small client-side effect rewrites the URL to include the stored
 *     value when the user lands without a param — keeps the URL the
 *     single source of truth at the same time.
 *
 * Stable contract:
 *   ?lens=story|evidence|audit         (default: story)
 *   ?view=briefing|dossier|forensic    (default: briefing)
 *   localStorage["dd-lens"] mirrors ?lens; ditto for "dd-view".
 *
 * The page passes the resolved values down to set the wrapper's
 * data-lens / data-density attributes so all visibility / ordering
 * decisions are CSS-driven.
 */

import React, { useCallback, useEffect } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import {
  parseDensity,
  parseLens,
  VALID_DENSITIES,
  VALID_LENSES,
  type DensityId,
  type LensId,
} from "@/lib/lens-density";

// Re-export the shared types for callers that previously imported them
// from this module (kept as a courtesy alias — new code should import
// directly from @/lib/lens-density).
export type { DensityId, LensId };

const LENS_STORAGE_KEY = "dd-lens";
const VIEW_STORAGE_KEY = "dd-view";

const LENS_LABELS: Record<LensId, string> = {
  story: "Story",
  evidence: "Evidence",
  compliance: "Compliance",
  audit: "Audit",
};
const LENS_HINTS: Record<LensId, string> = {
  story: "Attack stories first — kill chains, capability surface, then evidence",
  evidence: "Direct to per-rule evidence — no hero, no chains",
  compliance: "Restructured by framework controls (EU AI Act, ISO, OWASP, …)",
  audit: "Provenance-first — every claim footnoted with scan + rules version",
};

const DENSITY_LABELS: Record<DensityId, string> = {
  briefing: "Briefing",
  dossier: "Dossier",
  forensic: "Forensic",
};
const DENSITY_HINTS: Record<DensityId, string> = {
  briefing: "One-line-per-rule. Click any row to expand inline.",
  dossier: "Methodology open by default. Findings open on demand.",
  forensic: "Everything expanded — evidence chains, verification steps, references.",
};

export interface LensDensityControlsProps {
  /** Current values from the URL — resolved server-side and passed in
   *  so SSR and client always agree on the initial state. */
  lens: LensId;
  density: DensityId;
}

export default function LensDensityControls({
  lens,
  density,
}: LensDensityControlsProps) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const buildUrl = useCallback(
    (overrides: { lens?: LensId; view?: DensityId }) => {
      const params = new URLSearchParams(searchParams.toString());
      const nextLens = overrides.lens ?? lens;
      const nextView = overrides.view ?? density;
      // Drop the param when it equals the default — keeps shared URLs
      // shorter and signals "default" cleanly.
      if (nextLens === "story") params.delete("lens");
      else params.set("lens", nextLens);
      if (nextView === "briefing") params.delete("view");
      else params.set("view", nextView);
      const qs = params.toString();
      return qs ? `${pathname}?${qs}` : pathname;
    },
    [pathname, searchParams, lens, density],
  );

  // First-load reconciliation: when the URL has no ?lens / ?view but
  // localStorage holds a non-default value, rewrite the URL to match.
  // Skipped during SSR via the typeof window check; runs once on mount.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const urlHasLens = searchParams.has("lens");
    const urlHasView = searchParams.has("view");
    if (urlHasLens && urlHasView) return;
    const storedLens = !urlHasLens
      ? parseLens(window.localStorage.getItem(LENS_STORAGE_KEY))
      : lens;
    const storedView = !urlHasView
      ? parseDensity(window.localStorage.getItem(VIEW_STORAGE_KEY))
      : density;
    if (storedLens === lens && storedView === density) return;
    router.replace(buildUrl({ lens: storedLens, view: storedView }), {
      scroll: false,
    });
    // Intentionally only on mount — subsequent URL changes are driven by
    // explicit clicks below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onLensClick = useCallback(
    (next: LensId) => {
      if (next === lens) return;
      if (typeof window !== "undefined") {
        window.localStorage.setItem(LENS_STORAGE_KEY, next);
      }
      router.replace(buildUrl({ lens: next }), { scroll: false });
    },
    [router, buildUrl, lens],
  );

  const onDensityClick = useCallback(
    (next: DensityId) => {
      if (next === density) return;
      if (typeof window !== "undefined") {
        window.localStorage.setItem(VIEW_STORAGE_KEY, next);
      }
      router.replace(buildUrl({ view: next }), { scroll: false });
    },
    [router, buildUrl, density],
  );

  return (
    <div
      className="lds-controls"
      role="toolbar"
      aria-label="View controls"
    >
      <div
        className="lds-group"
        role="group"
        aria-label="Lens — what story this page tells"
      >
        <span className="lds-group-label">Lens</span>
        {VALID_LENSES.map((l) => {
          const active = l === lens;
          return (
            <button
              key={l}
              type="button"
              className={`lds-pill${active ? " lds-pill-active" : ""}`}
              data-active={active}
              onClick={() => onLensClick(l)}
              title={LENS_HINTS[l]}
              aria-pressed={active}
            >
              {LENS_LABELS[l]}
            </button>
          );
        })}
      </div>

      <div
        className="lds-group"
        role="group"
        aria-label="Density — how much detail per rule"
      >
        <span className="lds-group-label">Detail</span>
        {VALID_DENSITIES.map((d) => {
          const active = d === density;
          return (
            <button
              key={d}
              type="button"
              className={`lds-pill${active ? " lds-pill-active" : ""}`}
              data-active={active}
              onClick={() => onDensityClick(d)}
              title={DENSITY_HINTS[d]}
              aria-pressed={active}
            >
              {DENSITY_LABELS[d]}
            </button>
          );
        })}
      </div>
    </div>
  );
}

// Note: `resolveLensDensity` used to live here. It moved to
// `packages/web/src/lib/lens-density.ts` because Next 15 forbids server
// components from invoking functions exported from a "use client"
// module — `app/servers/[slug]/page.tsx` calls the helper during SSR.
// The function has no client-only deps (no hooks, no DOM), so it's now
// a server-callable lib export. See the docstring on that file.
