import { describe, it, expect } from "vitest";
import { ExcessiveDependencyCountRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-51-deps.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-extreme-count.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-75-deps.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-at-threshold.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-small-project.js";

const rule = new ExcessiveDependencyCountRule();

describe("D4 — Excessive Dependency Count (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags 51 deps (just over threshold)", () => {
      const results = rule.analyze(tp01());
      expect(results.length).toBe(1);
      expect(results[0].severity).toBe("low");
    });

    it("elevates factor weight for extreme count (>200)", () => {
      const results = rule.analyze(tp02());
      const factor = results[0].chain.confidence_factors.find(
        (f) => f.factor === "dependency_count_over_threshold",
      );
      expect(factor?.adjustment).toBe(0.1);
    });

    it("emits a single finding for 75 deps", () => {
      const results = rule.analyze(tp03());
      expect(results.length).toBe(1);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("passes exactly 50 deps (at threshold, not over)", () => {
      expect(rule.analyze(tn01())).toEqual([]);
    });

    it("passes a small project with 2 deps", () => {
      expect(rule.analyze(tn02())).toEqual([]);
    });
  });

  describe("chain integrity — v2 contract", () => {
    it("structured Locations and verification targets", () => {
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

    it("confidence capped at 0.60, cites SLSA", () => {
      const results = rule.analyze(tp02());
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.6);
        expect(r.chain.threat_reference?.id).toBe("SLSA-Supply-Chain-Levels");
      }
    });
  });
});
