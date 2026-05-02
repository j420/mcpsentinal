/**
 * Regression: server-component-level page render must NOT throw on a
 * deliberately partial deep-dive payload.
 *
 * Production hit a recurring 500 (digest 1844648646) because `dd.categories`
 * was being read as `dd.categories.length` directly — when the api
 * returns a partial response (older deploy, edge case) and `categories`
 * is null, that crash propagates straight to the route-level error.tsx
 * and HTTP 500. The page MUST coerce every nested array to a guaranteed
 * shape before rendering.
 *
 * This file tests the COERCION CONTRACT, not the React render. The page
 * itself is async + reads from `next/navigation` etc., which is awkward
 * to render under vitest. Instead we replicate the exact safe-coercion
 * lines from page.tsx and assert them against the precise shapes that
 * have caused crashes.
 */

import { describe, expect, it } from "vitest";

// The literal coercion logic from packages/web/src/app/servers/[slug]/page.tsx.
// If page.tsx ever drifts away from these lines, the test stops being
// a regression guard — a follow-up assertion at the bottom of the file
// re-reads the page source and asserts the lines are still present.
function safeCoerce(dd: Record<string, unknown>): {
  safeCategories: unknown[];
  safeAttackChains: unknown[] | undefined;
  safeRiskEdges: unknown[] | undefined;
  hasContent: boolean;
} {
  const safeCategories = Array.isArray(dd["categories"]) ? dd["categories"] : [];
  const safeAttackChains = Array.isArray(dd["attack_chains"])
    ? (dd["attack_chains"] as unknown[])
    : undefined;
  const safeRiskEdges = Array.isArray(dd["risk_edges"])
    ? (dd["risk_edges"] as unknown[])
    : undefined;
  const hasContent = (safeCategories as unknown[]).length > 0;
  return {
    safeCategories: safeCategories as unknown[],
    safeAttackChains,
    safeRiskEdges,
    hasContent,
  };
}

describe("page.tsx — safe coercion of partial deep-dive payloads", () => {
  it("survives a payload with categories: null (the production-1844648646 case)", () => {
    expect(() =>
      safeCoerce({
        server: { slug: "x", name: "x" },
        coverage: {},
        categories: null,
      }),
    ).not.toThrow();
    const out = safeCoerce({ categories: null });
    expect(out.safeCategories).toEqual([]);
    expect(out.hasContent).toBe(false);
  });

  it("survives a payload with categories OMITTED entirely", () => {
    expect(() => safeCoerce({})).not.toThrow();
    const out = safeCoerce({});
    expect(out.safeCategories).toEqual([]);
  });

  it("preserves a real categories array unchanged", () => {
    const cats = [{ id: "a" }, { id: "b" }];
    const out = safeCoerce({ categories: cats });
    expect(out.safeCategories).toBe(cats);
    expect(out.hasContent).toBe(true);
  });

  it("converts attack_chains to undefined when not an array (so KillChainReel renders nothing)", () => {
    const out = safeCoerce({ attack_chains: null });
    expect(out.safeAttackChains).toBeUndefined();
  });

  it("converts risk_edges to undefined when not an array", () => {
    const out = safeCoerce({ risk_edges: "definitely-not-an-array" });
    expect(out.safeRiskEdges).toBeUndefined();
  });

  it("survives every required field being null at once (pathological case)", () => {
    const dd = {
      server: null,
      coverage: null,
      categories: null,
      attack_chains: null,
      risk_edges: null,
      capability_node: null,
      provenance: null,
    };
    expect(() => safeCoerce(dd)).not.toThrow();
    const out = safeCoerce(dd);
    expect(out.safeCategories).toEqual([]);
    expect(out.safeAttackChains).toBeUndefined();
    expect(out.safeRiskEdges).toBeUndefined();
    expect(out.hasContent).toBe(false);
  });

  it("treats a categories[] containing null/undefined entries as still safe to map over", () => {
    // The page renders <SectionBoundary key={cat?.id ?? `cat-${i}`}> so
    // a null entry doesn't blow up the map.
    const out = safeCoerce({ categories: [null, { id: "x" }] });
    expect(out.safeCategories.length).toBe(2);
    expect(() =>
      out.safeCategories.map((cat: unknown, i: number) => ({
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        key: (cat as any)?.id ?? `cat-${i}`,
      })),
    ).not.toThrow();
  });
});

// Source-level guard: assert the page.tsx still uses the exact coercion
// lines this test is mirroring. If page.tsx drifts, this asserts loudly
// rather than silently — the regression test must always reflect the
// production code path it's protecting.
describe("page.tsx — source-level guard (the coercion lines exist verbatim)", () => {
  it("page.tsx still coerces categories / attack_chains / risk_edges to safe shapes", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const url = await import("node:url");
    const here = path.dirname(url.fileURLToPath(import.meta.url));
    const pagePath = path.resolve(
      here,
      "..",
      "app",
      "servers",
      "[slug]",
      "page.tsx",
    );
    const src = fs.readFileSync(pagePath, "utf-8");
    expect(src).toContain(
      "const safeCategories = Array.isArray(dd.categories) ? dd.categories : [];",
    );
    expect(src).toContain("const safeAttackChains = Array.isArray(dd.attack_chains)");
    expect(src).toContain("const safeRiskEdges = Array.isArray(dd.risk_edges)");
    // And the unsafe original `dd.categories.length` / `dd.categories.map`
    // patterns must NOT appear anywhere in page.tsx — they were the
    // 1844648646 crash source.
    expect(src).not.toContain("dd.categories.length");
    expect(src).not.toContain("dd.categories.map");
  });
});
