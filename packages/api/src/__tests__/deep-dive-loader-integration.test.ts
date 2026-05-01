/**
 * Deep-dive loader integration test — exercises `loadTaxonomy()` and
 * `loadRuleMethodology()` against the REAL on-disk files (no
 * `_setForTests` shim). Cluster D reviewer m5 (the eighth failure mode):
 *
 *   "When an endpoint loads an on-disk artifact at request time and
 *    projects it into a Zod-typed response, write at least one
 *    integration test that calls the loader against the real file
 *    and asserts the produced shape matches both the response schema
 *    and a non-trivial consumer access path."
 *
 * The synthetic-fixture suite at `server.test.ts` papers over loader/
 * file divergence — it replaces both loaders with `_setForTests` shims.
 * If the real YAML's field names diverge from the loader's expectations,
 * or if the `yaml` dep isn't reachable from this package, those tests
 * stay green while production serves `categories: []`.
 *
 * This file deliberately does NOT mock anything. It runs the real
 * loaders against the real files and asserts non-trivial truths about
 * the produced shape.
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  _resetDeepDiveLoadersForTests,
  loadTaxonomy,
  loadRuleMethodology,
} from "../deep-dive.js";

describe("Deep-dive loaders — real files", () => {
  beforeEach(() => {
    // Each test gets a fresh memoised state so failures in one don't
    // mask others.
    _resetDeepDiveLoadersForTests();
  });

  it("loadTaxonomy() reads the real attack-vectors.yaml and returns ≥1 category", async () => {
    const t = await loadTaxonomy();
    // If this fails: either yaml dep is unresolvable, or the YAML file
    // is missing at the resolved path, or the parser is rejecting the
    // file shape. Read the pino warn line printed during the test run
    // for the underlying reason.
    expect(t).not.toBeNull();
    expect(t!.categories.length).toBeGreaterThan(0);
  });

  it("loadTaxonomy() returns categories that each have ≥1 sub-category", async () => {
    const t = await loadTaxonomy();
    expect(t).not.toBeNull();
    for (const cat of t!.categories) {
      expect(cat.id.length).toBeGreaterThan(0);
      expect(cat.title.length).toBeGreaterThan(0);
      expect(cat.sub_categories.length).toBeGreaterThan(0);
    }
  });

  it("loadTaxonomy() sub-categories carry rule_ids (not the legacy `rules` key)", async () => {
    // Cluster D reviewer B2 lesson — the YAML uses `rule_ids`, not
    // `rules`. If the normaliser regresses to reading `rules`, every
    // sub-category drops to [] and the page renders empty categories.
    const t = await loadTaxonomy();
    expect(t).not.toBeNull();
    let totalRules = 0;
    for (const cat of t!.categories) {
      for (const sub of cat.sub_categories) {
        totalRules += sub.rules.length;
      }
    }
    // 163 active + 14 retired in the YAML; canonical placements + cross
    // references taken together populate well over 100 rule_ids across
    // sub-categories. A non-trivial threshold prevents a regression
    // where one sub-category accidentally has all rules and the rest
    // are empty.
    expect(totalRules).toBeGreaterThan(100);
  });

  it("loadRuleMethodology() reads the real rule-methodology.json and returns ≥1 rule", async () => {
    // Cluster D reviewer B3/B4 — the file is wrapped `{rules: {...}}`
    // and the entries are flat (no `rule_meta` nesting). The loader
    // unwraps + projects. If this fails the page renders rules with
    // empty methodology.
    const m = await loadRuleMethodology();
    expect(m).not.toBeNull();
    const ids = Object.keys(m!);
    expect(ids.length).toBeGreaterThan(0);
  });

  it("loadRuleMethodology() entries have technique + verified_edge_cases + rule_meta", async () => {
    const m = await loadRuleMethodology();
    expect(m).not.toBeNull();
    const ids = Object.keys(m!);
    expect(ids.length).toBeGreaterThan(100);
    // Sample a known rule that the analyzer has shipped since Phase 1.
    const k1 = m!["K1"];
    expect(k1).toBeDefined();
    expect(typeof k1!.technique).toBe("string");
    expect(k1!.technique.length).toBeGreaterThan(0);
    expect(Array.isArray(k1!.verified_edge_cases)).toBe(true);
    // The CHARTER for K1 declares ≥3 lethal edge cases per Rule
    // Standard v2; the loader should preserve that count after the
    // `lethal_edge_cases` → `verified_edge_cases` rename.
    expect(k1!.verified_edge_cases.length).toBeGreaterThanOrEqual(3);
    // rule_meta projection from flat extractor fields.
    expect(k1!.rule_meta.name.length).toBeGreaterThan(0);
    expect(["critical", "high", "medium", "low", "informational"]).toContain(
      k1!.rule_meta.severity,
    );
  });

  it("loadRuleMethodology() and loadTaxonomy() together cover most rules", async () => {
    // Cross-coverage assertion: the rules cited in the taxonomy YAML
    // should mostly appear in the methodology manifest. Any large
    // delta points to a build-script bug or a stale checked-in
    // artifact.
    const t = await loadTaxonomy();
    const m = await loadRuleMethodology();
    expect(t).not.toBeNull();
    expect(m).not.toBeNull();
    const taxonomyRuleIds = new Set<string>();
    for (const cat of t!.categories) {
      for (const sub of cat.sub_categories) {
        for (const r of sub.rules) taxonomyRuleIds.add(r);
      }
    }
    const methodologyIds = new Set(Object.keys(m!));
    let coveredCount = 0;
    for (const id of taxonomyRuleIds) {
      if (methodologyIds.has(id)) coveredCount++;
    }
    // Expect ≥80% overlap; a hard 100% would be brittle if a rule's
    // CHARTER is malformed or the build-script skipped it.
    const ratio = coveredCount / taxonomyRuleIds.size;
    expect(ratio).toBeGreaterThanOrEqual(0.8);
  });
});
