import { describe, it, expect } from "vitest";
import { KnownMaliciousPackagesRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-event-stream.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-mcp-scope-squat.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-cyrillic-homoglyph.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-clean-deps.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-similar-not-exact.js";

const rule = new KnownMaliciousPackagesRule();

describe("D5 — Known Malicious Packages (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags event-stream via exact match", () => {
      const results = rule.analyze(tp01());
      expect(results.length).toBe(1);
      expect(results[0].severity).toBe("critical");
      const factors = results[0].chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("confirmed_malicious_package_hit");
    });

    it("flags @mcp/sdk (scope-squat of @modelcontextprotocol/sdk)", () => {
      const results = rule.analyze(tp02());
      expect(results.length).toBe(1);
      const src = results[0].chain.links.find((l) => l.type === "source");
      const loc = src!.location;
      if (typeof loc !== "string" && loc.kind === "dependency") {
        expect(loc.name).toBe("@mcp/sdk");
      }
    });

    it("flags Cyrillic-homoglyph event-stream via Unicode normalisation", () => {
      const results = rule.analyze(tp03());
      expect(results.length).toBe(1);
      const factors = results[0].chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("unicode_homoglyph_normalisation_hit");
    });
  });

  describe("does not fire (true negatives)", () => {
    it("passes a clean dependency set", () => {
      expect(rule.analyze(tn01())).toEqual([]);
    });

    it("passes lexically-similar-but-not-exact 'eventstream' (D3's job, not D5's)", () => {
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

    it("confidence capped at 0.95, primary threat_reference is OWASP-MCP10-Supply-Chain", () => {
      const results = rule.analyze(tp01());
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.95);
        expect(r.chain.threat_reference?.id).toBe("OWASP-MCP10-Supply-Chain");
      }
    });
  });
});
