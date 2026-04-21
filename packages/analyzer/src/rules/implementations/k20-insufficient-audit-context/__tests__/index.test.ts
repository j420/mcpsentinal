/**
 * K20 v2 — functional + chain-integrity tests.
 *
 * Covers the mandated test matrix from the mission:
 *   - 3 true positives (string-only, only-msg object, template-literal)
 *   - 2 true negatives (adequate structured call, bindings-aware)
 *   - 1 evidence-integrity test (isLocation on every link + step target)
 *   - 1 confidence-ordering test (missing 3 fields > missing 1 field)
 *   - 1 mutation test (adding the missing field removes the finding)
 *   - plus a scoping-boundary test (K20 defers console.* to K1 when a
 *     structured logger is imported in the file)
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { K20InsufficientAuditContextRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function loadFixture(name: string): { file: string; text: string } {
  const file = join(FIXTURES_DIR, name);
  return { file, text: readFileSync(file, "utf8") };
}

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

const rule = new K20InsufficientAuditContextRule();

describe("K20 — Insufficient Audit Context in Logging (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags logger.info(<string-only>) with no object literal", () => {
      const { file, text } = loadFixture("true-positive-01-string-only.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].rule_id).toBe("K20");
      expect(results[0].severity).toBe("medium");
      const factors = results[0].chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("audit_fields_observed_count");
    });

    it("flags logger.info({ msg }) — object with no recognised aliases", () => {
      const { file, text } = loadFixture("true-positive-02-object-with-only-msg.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].rule_id).toBe("K20");
    });

    it("flags template-literal log call — interpolation is not structure", () => {
      const { file, text } = loadFixture("true-positive-03-template-literal-interpolation.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].rule_id).toBe("K20");
    });
  });

  describe("does not fire (true negatives)", () => {
    it("recognises an adequate structured log call with five audit fields", () => {
      const { file, text } = loadFixture("true-negative-01-structured-adequate.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("resolves pino.child({...}).info({...}) bindings across the receiver chain", () => {
      const { file, text } = loadFixture("true-negative-02-bindings-aware.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("defers bare console.* to K1 when a structured logger is imported in the file", () => {
      const { file, text } = loadFixture("true-negative-03-console-deferred-to-k1.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });
  });

  describe("evidence integrity — v2 contract", () => {
    const TP_FIXTURES = [
      "true-positive-01-string-only.ts",
      "true-positive-02-object-with-only-msg.ts",
      "true-positive-03-template-literal-interpolation.ts",
    ] as const;

    for (const name of TP_FIXTURES) {
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

      it(`${name} → confidence in (0.05, 0.85]`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.85);
          expect(r.chain.confidence).toBeGreaterThan(0.05);
        }
      });

      it(`${name} → cites ISO-27001-A.8.15 as the primary threat reference`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("ISO-27001-A.8.15");
        }
      });
    }
  });

  describe("confidence ordering — fewer observed fields → higher confidence", () => {
    it("missing-all (0 aliases) confidence > missing-most (1 alias)", () => {
      const zeroAliasesSrc =
        `declare const logger: { info: (...a: unknown[]) => void };\n` +
        `export function h(): void { logger.info("handled"); }\n`;
      const oneAliasSrc =
        `declare const logger: { info: (...a: unknown[]) => void };\n` +
        `export function h(requestId: string): void { logger.info({ requestId }); }\n`;

      const zeroResults = rule.analyze(makeContext("zero.ts", zeroAliasesSrc));
      const oneResults = rule.analyze(makeContext("one.ts", oneAliasSrc));

      expect(zeroResults.length).toBeGreaterThan(0);
      expect(oneResults.length).toBeGreaterThan(0);

      const zeroConf = zeroResults[0].chain.confidence;
      const oneConf = oneResults[0].chain.confidence;
      expect(zeroConf).toBeGreaterThan(oneConf);
    });
  });

  describe("mutation — adding the missing audit fields removes the finding", () => {
    it("string-only call gains required fields → K20 is silent", () => {
      const before =
        `declare const logger: { info: (...a: unknown[]) => void };\n` +
        `export function h(): void { logger.info("handled"); }\n`;
      const after =
        `declare const logger: { info: (...a: unknown[]) => void };\n` +
        `export function h(correlation_id: string, user_id: string): void {\n` +
        `  logger.info({ correlation_id, user_id }, "handled");\n` +
        `}\n`;

      const beforeFindings = rule.analyze(makeContext("before.ts", before));
      expect(beforeFindings.length).toBeGreaterThan(0);

      const afterFindings = rule.analyze(makeContext("after.ts", after));
      expect(afterFindings).toEqual([]);
    });
  });
});
