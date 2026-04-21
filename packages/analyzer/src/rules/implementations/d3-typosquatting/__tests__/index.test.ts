/**
 * D3 v2 — functional + chain-integrity tests.
 *
 * Every fixture under ../__fixtures__/ exports a buildContext() that
 * populates context.dependencies. We assert:
 *
 *   - TP fixtures produce at least one finding;
 *   - TN fixtures produce zero findings;
 *   - every finding has a source + sink link with structured Locations;
 *   - every VerificationStep.target is a Location;
 *   - confidence is in (0.30, 0.90];
 *   - the threat reference is ISO 27001 A.5.21.
 */

import { describe, it, expect } from "vitest";
import { readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { TyposquattingRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-lodash-typo.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-scope-squat.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-visual-confusable.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-legitimate-fork.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-versioned-package.js";
import { buildContext as tn03 } from "../__fixtures__/true-negative-03-popular-package.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

const rule = new TyposquattingRule();

type ContextBuilder = () => AnalysisContext;

const TP_BUILDERS: Record<string, ContextBuilder> = {
  "true-positive-01-lodash-typo.ts": tp01,
  "true-positive-02-scope-squat.ts": tp02,
  "true-positive-03-visual-confusable.ts": tp03,
};

describe("D3 — Typosquatting Risk (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags the confirmed typosquat lodahs → lodash", () => {
      const results = rule.analyze(tp01());
      expect(results.length).toBe(1);
      expect(results[0].rule_id).toBe("D3");
      expect(results[0].severity).toBe("critical");
      const factors = results[0].chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("confirmed_typosquat_registry_hit");
    });

    it("flags the scope squat @mcp/sdk → @modelcontextprotocol/sdk", () => {
      const results = rule.analyze(tp02());
      expect(results.length).toBe(1);
      expect(results[0].rule_id).toBe("D3");
      // This candidate appears in BOTH the confirmed-typosquat registry
      // AND would qualify as a scope-squat. The confirmed-typosquat
      // classifier runs first and wins.
      const factors = results[0].chain.confidence_factors.map((f) => f.factor);
      expect(
        factors.includes("confirmed_typosquat_registry_hit") ||
          factors.includes("scope_squat_of_official"),
      ).toBe(true);
    });

    it("flags the visual-confusable squat rnistral → mistral", () => {
      const results = rule.analyze(tp03());
      expect(results.length).toBe(1);
      expect(results[0].rule_id).toBe("D3");
      const factors = results[0].chain.confidence_factors.map((f) => f.factor);
      // Either the distance-only factor or the visual-confusable factor
      // is present — the classifier path may pick either based on ordering.
      expect(
        factors.includes("target_distance_under_threshold") ||
          factors.includes("visual_confusable_variant_matched"),
      ).toBe(true);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("passes the legitimate lodash-es fork", () => {
      expect(rule.analyze(tn01())).toEqual([]);
    });

    it("passes a numeric-suffix versioned package react-18", () => {
      expect(rule.analyze(tn02())).toEqual([]);
    });

    it("passes an exact canonical-target match (lodash)", () => {
      expect(rule.analyze(tn03())).toEqual([]);
    });
  });

  describe("chain integrity — v2 contract", () => {
    const fixtureNames = readdirSync(FIXTURES_DIR).filter((n) => n.startsWith("true-positive-"));

    for (const name of fixtureNames) {
      it(`${name} → every link has a structured Location`, () => {
        const builder = TP_BUILDERS[name];
        if (!builder) throw new Error(`missing context builder for ${name}`);
        const results = rule.analyze(builder());
        expect(results.length).toBeGreaterThan(0);
        for (const r of results) {
          const sourceLinks = r.chain.links.filter((l) => l.type === "source");
          const sinkLinks = r.chain.links.filter((l) => l.type === "sink");
          expect(sourceLinks.length).toBeGreaterThan(0);
          expect(sinkLinks.length).toBeGreaterThan(0);

          for (const link of r.chain.links) {
            if (link.type === "impact") continue;
            expect(
              isLocation(link.location),
              `${name} ${link.type} link location must be a structured Location, got ${JSON.stringify(link.location)}`,
            ).toBe(true);
          }
        }
      });

      it(`${name} → every VerificationStep.target is a Location`, () => {
        const builder = TP_BUILDERS[name];
        if (!builder) throw new Error(`missing context builder for ${name}`);
        const results = rule.analyze(builder());
        for (const r of results) {
          const steps = r.chain.verification_steps ?? [];
          expect(steps.length).toBeGreaterThan(0);
          for (const step of steps) {
            expect(
              isLocation(step.target),
              `${name} step ${step.step_type} target must be a Location, got ${JSON.stringify(step.target)}`,
            ).toBe(true);
          }
        }
      });

      it(`${name} → confidence capped at 0.90, floored above 0.30`, () => {
        const builder = TP_BUILDERS[name];
        if (!builder) throw new Error(`missing context builder for ${name}`);
        const results = rule.analyze(builder());
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.9);
          expect(r.chain.confidence).toBeGreaterThan(0.3);
        }
      });

      it(`${name} → cites ISO-27001-A.5.21 as primary threat reference`, () => {
        const builder = TP_BUILDERS[name];
        if (!builder) throw new Error(`missing context builder for ${name}`);
        const results = rule.analyze(builder());
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("ISO-27001-A.5.21");
        }
      });
    }
  });

  describe("structured Location shape", () => {
    it("emits a dependency Location with ecosystem, name, version", () => {
      const results = rule.analyze(tp01());
      const src = results[0].chain.links.find((l) => l.type === "source");
      expect(src).toBeDefined();
      const loc = src!.location;
      expect(isLocation(loc)).toBe(true);
      if (typeof loc !== "string" && loc.kind === "dependency") {
        expect(loc.ecosystem).toBe("npm");
        expect(loc.name).toBe("lodahs");
        expect(loc.version).toBe("4.17.21");
      } else {
        throw new Error("expected a dependency Location");
      }
    });

    it("emits a config Location with RFC 6901 json_pointer for the manifest", () => {
      const results = rule.analyze(tp02());
      const prop = results[0].chain.links.find((l) => l.type === "propagation");
      expect(prop).toBeDefined();
      const loc = prop!.location;
      expect(isLocation(loc)).toBe(true);
      if (typeof loc !== "string" && loc.kind === "config") {
        expect(loc.file).toBe("package.json");
        // "@mcp/sdk" → "/dependencies/@mcp~1sdk" under RFC 6901 escaping.
        expect(loc.json_pointer).toBe("/dependencies/@mcp~1sdk");
      } else {
        throw new Error("expected a config Location");
      }
    });
  });
});
