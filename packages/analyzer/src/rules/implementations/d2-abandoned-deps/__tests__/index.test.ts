import { describe, it, expect } from "vitest";
import { AbandonedDependenciesRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-abandoned-13-months.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-high-risk-48-months.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-pypi-abandoned.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-recent.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-null-last-updated.js";

const rule = new AbandonedDependenciesRule();

describe("D2 — Abandoned Dependencies (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags a 13-month-old package", () => {
      const results = rule.analyze(tp01());
      expect(results.length).toBe(1);
      expect(results[0].rule_id).toBe("D2");
      expect(results[0].severity).toBe("medium");
      const factors = results[0].chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("abandoned_age_over_threshold");
    });

    it("elevates factor weight for 48-month-old (high-risk) package", () => {
      const results = rule.analyze(tp02());
      const factor = results[0].chain.confidence_factors.find(
        (f) => f.factor === "abandoned_age_over_threshold",
      );
      expect(factor?.adjustment).toBe(0.15);
    });

    it("handles pypi packages", () => {
      const results = rule.analyze(tp03());
      expect(results.length).toBe(1);
      const src = results[0].chain.links.find((l) => l.type === "source");
      const loc = src!.location;
      if (typeof loc !== "string" && loc.kind === "dependency") {
        expect(loc.ecosystem).toBe("pypi");
      }
    });
  });

  describe("does not fire (true negatives)", () => {
    it("passes a recently updated package", () => {
      expect(rule.analyze(tn01())).toEqual([]);
    });

    it("skips silently when last_updated is null (edge case)", () => {
      expect(rule.analyze(tn02())).toEqual([]);
    });
  });

  describe("chain integrity — v2 contract", () => {
    it("every link has a structured Location and verification steps target Locations", () => {
      const results = rule.analyze(tp01());
      for (const r of results) {
        for (const link of r.chain.links) {
          if (link.type === "impact") continue;
          expect(isLocation(link.location)).toBe(true);
        }
        for (const step of r.chain.verification_steps ?? []) {
          expect(isLocation(step.target)).toBe(true);
        }
      }
    });

    it("confidence capped at 0.70 and cites OWASP-A062021", () => {
      const results = rule.analyze(tp02());
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.7);
        expect(r.chain.confidence).toBeGreaterThan(0.3);
        expect(r.chain.threat_reference?.id).toBe("OWASP-A062021");
      }
    });
  });
});
