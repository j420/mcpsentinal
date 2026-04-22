import { describe, it, expect } from "vitest";
import { WeakCryptographyDependenciesRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { isBelow, parseVersion, compareVersion } from "../data/semver.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-md5.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-node-forge-below-safe.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-pycrypto-abandoned.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-node-forge-safe.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-pycryptodome-modern.js";

const rule = new WeakCryptographyDependenciesRule();

describe("D6 — Weak Cryptography Dependencies (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags md5 (no safe version)", () => {
      const results = rule.analyze(tp01());
      expect(results.length).toBe(1);
      expect(results[0].severity).toBe("high");
    });

    it("flags node-forge 1.2.0 (below safe 1.3.0)", () => {
      const results = rule.analyze(tp02());
      expect(results.length).toBe(1);
      const factors = results[0].chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("below_safe_semver_floor");
    });

    it("flags pycrypto (abandoned library)", () => {
      const results = rule.analyze(tp03());
      expect(results.length).toBe(1);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("passes node-forge 1.3.0 (exactly at safe floor)", () => {
      expect(rule.analyze(tn01())).toEqual([]);
    });

    it("passes pycryptodome (maintained fork, name-family heuristic forbidden)", () => {
      expect(rule.analyze(tn02())).toEqual([]);
    });
  });

  describe("semver utility", () => {
    it("parses x.y.z versions", () => {
      expect(parseVersion("1.3.0")?.major).toBe(1);
      expect(parseVersion("4.2.0")?.minor).toBe(2);
    });

    it("handles prerelease < release at same x.y.z", () => {
      const a = parseVersion("1.0.0-alpha")!;
      const b = parseVersion("1.0.0")!;
      expect(compareVersion(a, b)).toBeLessThan(0);
    });

    it("isBelow returns true for 1.2.0 < 1.3.0", () => {
      expect(isBelow("1.2.0", "1.3.0")).toBe(true);
    });

    it("isBelow returns false for equal versions", () => {
      expect(isBelow("1.3.0", "1.3.0")).toBe(false);
    });
  });

  describe("chain integrity — v2 contract", () => {
    it("structured Locations + verification targets", () => {
      const results = rule.analyze(tp02());
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

    it("confidence capped at 0.88, cites CWE-327", () => {
      const results = rule.analyze(tp01());
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.88);
        expect(r.chain.threat_reference?.id).toBe("CWE-327");
      }
    });
  });
});
