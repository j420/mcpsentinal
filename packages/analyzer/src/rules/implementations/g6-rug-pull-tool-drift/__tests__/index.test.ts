/**
 * G6 v2 — functional + chain-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { RugPullToolDriftRule } from "../index.js";
import { isLocation } from "../../../location.js";

import { buildContext as tp1 } from "../__fixtures__/true-positive-01-dangerous-new-tool.js";
import { buildContext as tp2 } from "../__fixtures__/true-positive-02-description-mutation.js";
import { buildContext as tp3 } from "../__fixtures__/true-positive-03-large-addition-batch.js";
import { buildContext as tn1 } from "../__fixtures__/true-negative-01-stable-surface.js";
import { buildContext as tn2 } from "../__fixtures__/true-negative-02-no-baseline.js";

const rule = new RugPullToolDriftRule();

describe("G6 — Rug Pull / Tool Behavior Drift (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags a dangerous new tool added after baseline", () => {
      const results = rule.analyze(tp1());
      expect(results.length).toBe(1);
      const factors = results[0].chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("baseline_reference");
      expect(factors).toContain("dangerous_new_tool");
      expect(results[0].severity).toBe("critical");
    });

    it("flags description-hash mutation on an existing tool", () => {
      const results = rule.analyze(tp2());
      expect(results.length).toBe(1);
      const links = results[0].chain.links;
      // Modified-tool verification step must be present.
      const steps = results[0].chain.verification_steps ?? [];
      const compareBaselineSteps = steps.filter((s) => s.step_type === "compare-baseline");
      expect(compareBaselineSteps.length).toBeGreaterThan(0);
      expect(links.length).toBeGreaterThan(0);
    });

    it("flags a >5 tool addition batch (large-addition-batch signal)", () => {
      const results = rule.analyze(tp3());
      expect(results.length).toBe(1);
      const factors = results[0].chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("large_addition_batch");
    });
  });

  describe("does not fire (true negatives)", () => {
    it("skips a server whose tool surface matches the baseline exactly", () => {
      expect(rule.analyze(tn1())).toEqual([]);
    });

    it("skips a first-scan server with no previous_tool_pin (charter requirement)", () => {
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

      it(`${label} → confidence capped at 0.40 (weak baseline), floored above 0.05`, () => {
        const results = rule.analyze(build());
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.4);
          expect(r.chain.confidence).toBeGreaterThan(0.05);
        }
      });

      it(`${label} → cites Embrace The Red rug-pull paper`, () => {
        const results = rule.analyze(build());
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("EmbraceTheRed-2025-MCP-Rug-Pull");
        }
      });
    }
  });
});
