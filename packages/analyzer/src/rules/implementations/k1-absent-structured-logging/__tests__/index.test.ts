/**
 * K1 v2 — functional + chain-integrity tests.
 *
 * Every fixture under ../__fixtures__/ is loaded as a source file into a
 * synthetic AnalysisContext and handed to the rule. We assert:
 *
 *   - TP fixtures produce at least one finding;
 *   - TN fixtures produce zero findings;
 *   - every finding has a source link and a sink link with structured
 *     Locations (not prose strings);
 *   - every VerificationStep.target is a Location, not a string;
 *   - confidence is in [0.30, 0.90] (lower bound because we have full flow
 *     proof; upper bound is the charter cap);
 *   - the threat reference is ISO 27001 A.8.15 (the charter's primary cite).
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { AbsentStructuredLoggingRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function makeContext(file: string, text: string): AnalysisContext {
  return {
    server: { id: "srv-1", name: "test-server", description: null, github_url: null },
    tools: [],
    source_code: text,
    source_files: new Map([[file, text]]),
    dependencies: [],
    connection_metadata: null,
  };
}

function loadFixture(name: string): { file: string; text: string } {
  const file = join(FIXTURES_DIR, name);
  return { file, text: readFileSync(file, "utf8") };
}

const rule = new AbsentStructuredLoggingRule();

describe("K1 — Absent Structured Logging (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags console.log in an Express handler with no logger imported", () => {
      const { file, text } = loadFixture("true-positive-01-express-console.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        expect(r.rule_id).toBe("K1");
        expect(r.severity).toBe("high");
      }
    });

    it("flags a partial-migration handler (logger imported, not used in handler)", () => {
      const { file, text } = loadFixture("true-positive-02-partial-migration.ts");
      const results = rule.analyze(makeContext(file, text));
      // Exactly one finding: the legacy GET handler. The POST handler uses logger.info.
      expect(results.length).toBe(1);
      // The factor for "import present but unused" should be recorded.
      const factors = results[0].chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("logger_import_present_but_unused");
    });

    it("flags an explicit logger.silent = true suppression", () => {
      const { file, text } = loadFixture("true-positive-03-disable-suppression.ts");
      const results = rule.analyze(makeContext(file, text));
      // At least the suppression finding. The POST handler uses logger.info correctly,
      // so the handler-variant finding should NOT appear.
      expect(results.length).toBeGreaterThanOrEqual(1);
      const factors = results.flatMap((r) => r.chain.confidence_factors.map((f) => f.factor));
      expect(factors).toContain("explicit_disable");
    });
  });

  describe("does not fire (true negatives)", () => {
    it("recognises a pino-correct Express server", () => {
      const { file, text } = loadFixture("true-negative-01-pino-correct.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("resolves an alias binding (const l = pino())", () => {
      const { file, text } = loadFixture("true-negative-02-alias-binding.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("skips a structurally-identified test file (no .test suffix required)", () => {
      const { file, text } = loadFixture("true-negative-03-test-file.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("ignores console.log inside a non-handler utility function", () => {
      const { file, text } = loadFixture("true-negative-04-utility-not-handler.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });
  });

  describe("chain integrity — v2 contract", () => {
    const all = readdirSync(FIXTURES_DIR).filter((n) => n.startsWith("true-positive-"));
    for (const name of all) {
      it(`${name} → every link has a structured Location`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
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

      it(`${name} → every VerificationStep.target is a structured Location`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
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
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.9);
          expect(r.chain.confidence).toBeGreaterThan(0.3);
        }
      });

      it(`${name} → cites ISO-27001-A.8.15 as primary threat reference`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("ISO-27001-A.8.15");
        }
      });
    }
  });
});
