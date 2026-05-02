/**
 * Regression: ForensicTrigger MUST be wrapped in a <Suspense/> boundary
 * inside RuleEvidenceCard.
 *
 * Production hit a recurring HTTP 500 on /servers/[slug] for any server
 * that had at least one finding. Diagnosis:
 *
 *   - ForensicTrigger reads `useSearchParams()` (preserves other query
 *     params when it writes `?finding=<id>`).
 *   - Next 15 requires every `useSearchParams` consumer to live under a
 *     Suspense boundary. Without one, the prerender bails with
 *     MISSING_SUSPENSE_WITH_CSR_BAILOUT.
 *   - That bailout is a framework-level error; it bypasses the page's
 *     <SectionBoundary/> class error boundaries and propagates to the
 *     route-level error.tsx, surfacing as HTTP 500.
 *   - The other four `useSearchParams` consumers on the Deep Dive page
 *     (LensDensityControls, DeepDiveSidebar, ForensicDrawer,
 *     MobileNavigateFAB) are wrapped at their mount sites in page.tsx.
 *     ForensicTrigger is mounted indirectly inside RuleEvidenceCard's
 *     finding-action row, so the matching wrap lives there.
 *
 * This file asserts the structural invariant directly on the source.
 * Same pattern as `page-safe-coercion.test.ts` — a source-level regression
 * guard that fails loudly if the wrap is removed in a refactor. The
 * companion behavioral coverage lives in `RuleEvidenceCard.test.tsx`,
 * which mocks next/navigation so the trigger renders without throwing.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const CARD_SOURCE = readFileSync(
  resolve(__dirname, "..", "components", "RuleEvidenceCard.tsx"),
  "utf-8",
);

describe("RuleEvidenceCard — Suspense boundary around ForensicTrigger", () => {
  it("imports Suspense from react", () => {
    // Either `import React, { Suspense }` or `import { Suspense }` is fine.
    const importsSuspense =
      /import\s+[^;]*\bSuspense\b[^;]*from\s+["']react["']/.test(CARD_SOURCE);
    expect(importsSuspense).toBe(true);
  });

  it("wraps the ForensicTrigger mount in a <Suspense> boundary", () => {
    // The trigger appears exactly once in the source. Find that occurrence
    // and verify the nearest enclosing JSX opening tag is <Suspense>.
    const triggerIdx = CARD_SOURCE.indexOf("<ForensicTrigger");
    expect(triggerIdx).toBeGreaterThan(-1);

    // Look back ~400 chars for an unmatched <Suspense ... > opener. The
    // wrap is small (a few lines) so this window is plenty without
    // requiring a full JSX parser.
    const window = CARD_SOURCE.slice(Math.max(0, triggerIdx - 400), triggerIdx);
    expect(window).toMatch(/<Suspense\b[^>]*>/);

    // Closing </Suspense> must appear within ~400 chars after the trigger.
    const after = CARD_SOURCE.slice(
      triggerIdx,
      Math.min(CARD_SOURCE.length, triggerIdx + 400),
    );
    expect(after).toMatch(/<\/Suspense>/);
  });

  it("does NOT mount ForensicTrigger anywhere outside the Suspense boundary", () => {
    // Defensive: a future refactor might add another mount site. Every
    // occurrence of `<ForensicTrigger` must be wrapped. We assert the
    // count of `<ForensicTrigger` equals the count of <Suspense> ...
    // </Suspense> pairs that contain a ForensicTrigger inside them.
    const triggerCount = (CARD_SOURCE.match(/<ForensicTrigger/g) ?? []).length;
    expect(triggerCount).toBeGreaterThan(0);

    // Each trigger occurrence must have a Suspense opener within 400 chars
    // before it. Easier: split on <ForensicTrigger and check each preceding
    // segment ends with a Suspense opener that's still open.
    const segments = CARD_SOURCE.split("<ForensicTrigger");
    // First segment is the prelude; the remaining `triggerCount` segments
    // each follow a trigger occurrence.
    for (let i = 0; i < triggerCount; i++) {
      const before = segments[i].slice(-400);
      const lastSuspenseOpen = before.lastIndexOf("<Suspense");
      const lastSuspenseClose = before.lastIndexOf("</Suspense>");
      expect(lastSuspenseOpen).toBeGreaterThan(-1);
      // The opener must come AFTER any earlier closer in the window —
      // otherwise the trigger would sit outside the boundary.
      expect(lastSuspenseOpen).toBeGreaterThan(lastSuspenseClose);
    }
  });
});
