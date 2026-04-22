import { describe, it, expect } from "vitest";
import { ExcessiveToolCountRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-51-tools.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-excessive-150-tools.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-75-tools.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-at-threshold.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-small-server.js";

const rule = new ExcessiveToolCountRule();

describe("E4 — Excessive Tool Count (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags 51 tools", () => {
      const results = rule.analyze(tp01());
      expect(results.length).toBe(1);
      expect(results[0].severity).toBe("medium");
    });

    it("elevates factor for excessive tool count (>100)", () => {
      const results = rule.analyze(tp02());
      const factor = results[0].chain.confidence_factors.find(
        (f) => f.factor === "tool_count_over_threshold",
      );
      expect(factor?.adjustment).toBe(0.1);
    });

    it("fires on 75 tools at standard weight", () => {
      const results = rule.analyze(tp03());
      expect(results.length).toBe(1);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("passes exactly 50 tools (not over)", () => {
      expect(rule.analyze(tn01())).toEqual([]);
    });

    it("passes small server with 2 tools", () => {
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

    it("confidence capped at 0.65, cites INVARIANT-LABS-CONSENT-FATIGUE-2025", () => {
      const results = rule.analyze(tp01());
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.65);
        expect(r.chain.threat_reference?.id).toBe("INVARIANT-LABS-CONSENT-FATIGUE-2025");
      }
    });
  });
});
