/**
 * lens-density — pure helpers for the Deep Dive `?lens=` / `?view=` URL
 * params. Server-callable.
 *
 * Why this lives in lib/ and not in components/:
 *   The original implementation co-located these helpers with
 *   `LensDensityControls.tsx`, but that file is `"use client"` because
 *   the controls themselves use `useRouter` / `useSearchParams`. Next 15
 *   strictly forbids server components from CALLING functions exported
 *   from a `"use client"` module — exports are only allowed to be
 *   passed as props to client components or rendered as JSX. Calling
 *   `resolveLensDensity(sp)` from `app/servers/[slug]/page.tsx` (a
 *   server component) crashed SSR with:
 *
 *     Error: Attempted to call resolveLensDensity() from the server
 *     but resolveLensDensity is on the client. (digest 1244316665)
 *
 *   The error is framework-level — it bypasses the page's
 *   `<SectionBoundary/>` boundaries and surfaces as HTTP 500 from
 *   error.tsx. The five fields parsed here have no client-only deps
 *   (no hooks, no DOM, no `next/navigation`), so they belong in a
 *   server-callable module shared by both the page and the controls.
 *
 * Stable contract (unchanged):
 *   ?lens=story|evidence|compliance|audit   (default: story)
 *   ?view=briefing|dossier|forensic         (default: briefing)
 */

export type LensId = "story" | "evidence" | "compliance" | "audit";
export type DensityId = "briefing" | "dossier" | "forensic";

export const VALID_LENSES: ReadonlyArray<LensId> = [
  "story",
  "evidence",
  "compliance",
  "audit",
];

export const VALID_DENSITIES: ReadonlyArray<DensityId> = [
  "briefing",
  "dossier",
  "forensic",
];

export function parseLens(raw: string | null | undefined): LensId {
  if (!raw) return "story";
  return (VALID_LENSES as ReadonlyArray<string>).includes(raw)
    ? (raw as LensId)
    : "story";
}

export function parseDensity(raw: string | null | undefined): DensityId {
  if (!raw) return "briefing";
  return (VALID_DENSITIES as ReadonlyArray<string>).includes(raw)
    ? (raw as DensityId)
    : "briefing";
}

/**
 * Resolve the lens/density pair from the route's `searchParams`. Tolerant
 * of the `string | string[] | undefined` shape Next 15 produces; arrays
 * collapse to their first entry. Returns the documented defaults when the
 * input is absent or unrecognised.
 */
export function resolveLensDensity(
  raw: { lens?: string | string[]; view?: string | string[] } | undefined,
): { lens: LensId; density: DensityId } {
  if (!raw) return { lens: "story", density: "briefing" };
  const lensRaw = Array.isArray(raw.lens) ? raw.lens[0] : raw.lens;
  const viewRaw = Array.isArray(raw.view) ? raw.view[0] : raw.view;
  return { lens: parseLens(lensRaw), density: parseDensity(viewRaw) };
}
