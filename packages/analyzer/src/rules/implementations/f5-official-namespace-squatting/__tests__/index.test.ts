/**
 * F5 v2 — functional + chain-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { OfficialNamespaceSquattingRule } from "../index.js";
import { isLocation } from "../../../location.js";

import { buildContext as tp1 } from "../__fixtures__/true-positive-01-substring-containment.js";
import { buildContext as tp2 } from "../__fixtures__/true-positive-02-levenshtein-distance-one.js";
import { buildContext as tp3 } from "../__fixtures__/true-positive-03-visual-confusable.js";
import { buildContext as tn1 } from "../__fixtures__/true-negative-01-verified-publisher.js";
import { buildContext as tn2 } from "../__fixtures__/true-negative-02-unrelated-name.js";

const rule = new OfficialNamespaceSquattingRule();

describe("F5 — Official Namespace Squatting (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags substring containment with non-vendor github_url", () => {
      const results = rule.analyze(tp1());
      expect(results.length).toBeGreaterThan(0);
      const factors = results.flatMap((r) => r.chain.confidence_factors.map((f) => f.factor));
      expect(factors).toContain("official_namespace_signal");
      expect(factors).toContain("publisher_url_mismatch");
      for (const r of results) {
        expect(r.rule_id).toBe("F5");
        expect(r.severity).toBe("critical");
      }
    });

    it("flags Damerau-Levenshtein distance-1 typosquat of 'anthropic'", () => {
      const results = rule.analyze(tp2());
      expect(results.length).toBeGreaterThan(0);
      const r = results[0];
      const sourceLink = r.chain.links.find((l) => l.type === "source");
      expect(sourceLink?.type === "source" && sourceLink.observed).toBeTruthy();
    });

    it("flags visual-confusable substitution (0→o → 'google')", () => {
      const results = rule.analyze(tp3());
      expect(results.length).toBeGreaterThan(0);
      const observations = results.flatMap((r) =>
        r.chain.links.filter((l) => l.type === "source").map((l) => (l.type === "source" ? l.observed : "")),
      );
      expect(observations.some((o) => o.toLowerCase().includes("visual"))).toBe(true);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("skips server with verified Anthropic GitHub org", () => {
      expect(rule.analyze(tn1())).toEqual([]);
    });

    it("skips server name unrelated to any vendor namespace", () => {
      expect(rule.analyze(tn2())).toEqual([]);
    });
  });

  describe("chain integrity — v2 contract", () => {
    const fixtures = [tp1, tp2, tp3] as const;
    for (let i = 0; i < fixtures.length; i++) {
      const build = fixtures[i];
      const label = `tp${i + 1}`;

      it(`${label} → every link has a structured Location`, () => {
        const results = rule.analyze(build());
        expect(results.length).toBeGreaterThan(0);
        for (const r of results) {
          const sourceLinks = r.chain.links.filter((l) => l.type === "source");
          const sinkLinks = r.chain.links.filter((l) => l.type === "sink");
          expect(sourceLinks.length).toBeGreaterThan(0);
          expect(sinkLinks.length).toBeGreaterThan(0);
          for (const link of r.chain.links) {
            if (link.type === "impact") continue;
            expect(isLocation(link.location)).toBe(true);
          }
        }
      });

      it(`${label} → every VerificationStep.target is a structured Location`, () => {
        const results = rule.analyze(build());
        for (const r of results) {
          const steps = r.chain.verification_steps ?? [];
          expect(steps.length).toBeGreaterThan(0);
          for (const step of steps) {
            expect(isLocation(step.target)).toBe(true);
          }
        }
      });

      it(`${label} → confidence capped at 0.90, floored above 0.30`, () => {
        const results = rule.analyze(build());
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.9);
          expect(r.chain.confidence).toBeGreaterThan(0.3);
        }
      });

      it(`${label} → cites OWASP-MCP10-Supply-Chain`, () => {
        const results = rule.analyze(build());
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("OWASP-MCP10-Supply-Chain");
        }
      });
    }
  });
});
