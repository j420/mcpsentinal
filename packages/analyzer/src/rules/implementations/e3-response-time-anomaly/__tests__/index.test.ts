import { describe, it, expect } from "vitest";
import { ResponseTimeAnomalyRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-15-seconds.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-extreme-60-seconds.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-just-over-threshold.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-at-threshold.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-fast-response.js";

const rule = new ResponseTimeAnomalyRule();

describe("E3 — Response Time Anomaly (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags 15,000ms response", () => {
      const results = rule.analyze(tp01());
      expect(results.length).toBe(1);
      expect(results[0].severity).toBe("low");
    });

    it("elevates factor weight for extreme response times (>30s)", () => {
      const results = rule.analyze(tp02());
      const factor = results[0].chain.confidence_factors.find(
        (f) => f.factor === "response_time_over_threshold",
      );
      expect(factor?.adjustment).toBe(0.1);
    });

    it("fires on 10,001ms (strict > 10,000ms)", () => {
      const results = rule.analyze(tp03());
      expect(results.length).toBe(1);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("passes exactly 10,000ms (not over)", () => {
      expect(rule.analyze(tn01())).toEqual([]);
    });

    it("passes fast response (400ms)", () => {
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

    it("confidence capped at 0.65, cites OWASP-MCP09-Logging-Monitoring", () => {
      const results = rule.analyze(tp01());
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.65);
        expect(r.chain.threat_reference?.id).toBe("OWASP-MCP09-Logging-Monitoring");
      }
    });
  });
});
