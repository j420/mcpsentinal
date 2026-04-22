import { describe, it, expect } from "vitest";
import { KnownCvesInDependenciesRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-lodash-cve.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-multi-cve.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-pypi-cve.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-clean-dep.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-flag-no-ids.js";
import { buildContext as tn03 } from "../__fixtures__/true-negative-03-git-url-pin.js";

const rule = new KnownCvesInDependenciesRule();

describe("D1 — Known CVEs in Dependencies (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags lodash@4.17.10 with CVE-2019-10744", () => {
      const results = rule.analyze(tp01());
      expect(results.length).toBe(1);
      expect(results[0].rule_id).toBe("D1");
      expect(results[0].severity).toBe("high");
      const sinks = results[0].chain.links.filter((l) => l.type === "sink");
      expect(sinks[0]).toMatchObject({ cve_precedent: "CVE-2019-10744" });
    });

    it("emits multi_cve_dependency factor when ≥2 CVEs", () => {
      const results = rule.analyze(tp02());
      expect(results.length).toBe(1);
      const factors = results[0].chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("multi_cve_dependency");
    });

    it("handles pypi dependencies with underscores in name", () => {
      const results = rule.analyze(tp03());
      expect(results.length).toBe(1);
      const src = results[0].chain.links.find((l) => l.type === "source");
      expect(src).toBeDefined();
      const loc = src!.location;
      if (typeof loc !== "string" && loc.kind === "dependency") {
        expect(loc.ecosystem).toBe("pypi");
        expect(loc.name).toBe("requests_toolbelt");
      } else {
        throw new Error("expected dependency Location");
      }
    });
  });

  describe("does not fire (true negatives)", () => {
    it("passes a clean dependency without a CVE flag", () => {
      expect(rule.analyze(tn01())).toEqual([]);
    });

    it("skips silently when has_known_cve=true but cve_ids=[] (edge case)", () => {
      expect(rule.analyze(tn02())).toEqual([]);
    });

    it("skips silently when version is null (git-url pin edge case)", () => {
      expect(rule.analyze(tn03())).toEqual([]);
    });
  });

  describe("chain integrity — v2 contract", () => {
    it("every link has a structured Location and VerificationStep targets are Locations", () => {
      const results = rule.analyze(tp01());
      for (const r of results) {
        const sources = r.chain.links.filter((l) => l.type === "source");
        const sinks = r.chain.links.filter((l) => l.type === "sink");
        expect(sources.length).toBeGreaterThan(0);
        expect(sinks.length).toBeGreaterThan(0);
        for (const link of r.chain.links) {
          if (link.type === "impact") continue;
          expect(isLocation(link.location)).toBe(true);
        }
        const steps = r.chain.verification_steps ?? [];
        expect(steps.length).toBeGreaterThan(0);
        for (const step of steps) {
          expect(isLocation(step.target)).toBe(true);
        }
      }
    });

    it("confidence is capped at 0.92 and cites ISO-27001-A.8.8", () => {
      const results = rule.analyze(tp02());
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.92);
        expect(r.chain.confidence).toBeGreaterThan(0.3);
        expect(r.chain.threat_reference?.id).toBe("ISO-27001-A.8.8");
      }
    });
  });
});
