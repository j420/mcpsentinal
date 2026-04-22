import { describe, it, expect } from "vitest";
import { DependencyConfusionAttackRiskRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-9999-birsan-classic.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-major-100.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-known-private-namespace.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-unscoped-high-version.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-scoped-normal-version.js";

const rule = new DependencyConfusionAttackRiskRule();

describe("D7 — Dependency Confusion Attack Risk (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags @acme/internal-utils@9999.0.0 (Birsan classic)", () => {
      const results = rule.analyze(tp01());
      expect(results.length).toBe(1);
      expect(results[0].severity).toBe("high");
      const factor = results[0].chain.confidence_factors.find(
        (f) => f.factor === "suspicious_major_version",
      );
      expect(factor?.adjustment).toBe(0.15);
    });

    it("flags @company/private-sdk@100.0.0 at standard factor weight", () => {
      const results = rule.analyze(tp02());
      expect(results.length).toBe(1);
      const factor = results[0].chain.confidence_factors.find(
        (f) => f.factor === "suspicious_major_version",
      );
      expect(factor?.adjustment).toBe(0.09);
    });

    it("elevates factor for known private namespace prefix", () => {
      const results = rule.analyze(tp03());
      const factors = results[0].chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("known_private_namespace_prefix_match");
    });
  });

  describe("does not fire (true negatives)", () => {
    it("skips unscoped packages even with high version", () => {
      expect(rule.analyze(tn01())).toEqual([]);
    });

    it("passes scoped packages with normal version numbers", () => {
      expect(rule.analyze(tn02())).toEqual([]);
    });
  });

  describe("chain integrity — v2 contract", () => {
    it("structured Locations + verification targets", () => {
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

    it("confidence capped at 0.80, cites BIRSAN-2021", () => {
      const results = rule.analyze(tp01());
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.8);
        expect(r.chain.threat_reference?.id).toBe("BIRSAN-2021");
      }
    });
  });
});
