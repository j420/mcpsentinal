import { describe, it, expect } from "vitest";
import { InsecureTransportRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-http.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-ws.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-http-uppercase.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-https.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-stdio.js";

const rule = new InsecureTransportRule();

describe("E2 — Insecure Transport (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags http", () => {
      const results = rule.analyze(tp01());
      expect(results.length).toBe(1);
      expect(results[0].severity).toBe("high");
    });

    it("flags ws", () => {
      const results = rule.analyze(tp02());
      expect(results.length).toBe(1);
    });

    it("handles case-insensitive transport labels", () => {
      const results = rule.analyze(tp03());
      expect(results.length).toBe(1);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("passes https", () => {
      expect(rule.analyze(tn01())).toEqual([]);
    });

    it("skips stdio (not network-exposed)", () => {
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

    it("confidence capped at 0.85, cites CWE-319", () => {
      const results = rule.analyze(tp01());
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.85);
        expect(r.chain.threat_reference?.id).toBe("CWE-319");
      }
    });
  });
});
