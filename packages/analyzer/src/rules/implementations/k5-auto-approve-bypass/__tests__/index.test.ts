/**
 * K5 v2 — Auto-Approve / Bypass Confirmation: functional + chain tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { AutoApproveBypassRule } from "../index.js";
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
  return { file: `src/${name}`, text: readFileSync(join(FIXTURES_DIR, name), "utf8") };
}

const rule = new AutoApproveBypassRule();

describe("K5 — Auto-Approve / Bypass Confirmation (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags a { auto_approve: true } object property", () => {
      const { file, text } = loadFixture("true-positive-01-flag-assignment.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        expect(r.rule_id).toBe("K5");
        expect(r.severity).toBe("critical");
      }
      const factors = results.flatMap((r) => r.chain.confidence_factors.map((f) => f.factor));
      expect(factors).toContain("auto_approve_signal");
    });

    it("flags process.env.MCP_AUTO_APPROVE env-var bypass", () => {
      const { file, text } = loadFixture("true-positive-02-env-var.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
    });

    it("flags neutered confirmation stub (`return Promise.resolve(true)`)", () => {
      const { file, text } = loadFixture("true-positive-03-neutered-stub.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const oversight = results[0].chain.confidence_factors.find(
        (f) => f.factor === "oversight_bypass_scope",
      );
      expect(oversight?.adjustment).toBeGreaterThanOrEqual(0.1);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("does not fire on honest interactive confirmation", () => {
      const { file, text } = loadFixture("true-negative-01-honest-confirm.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("does not fire on unrelated business logic", () => {
      const { file, text } = loadFixture("true-negative-02-no-bypass-reachable.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });
  });

  describe("chain integrity — v2 contract", () => {
    const tps = readdirSync(FIXTURES_DIR).filter((n) => n.startsWith("true-positive-"));

    for (const name of tps) {
      it(`${name} → every link has a structured Location`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        expect(results.length).toBeGreaterThan(0);
        for (const r of results) {
          const sources = r.chain.links.filter((l) => l.type === "source");
          const sinks = r.chain.links.filter((l) => l.type === "sink");
          expect(sources.length).toBeGreaterThan(0);
          expect(sinks.length).toBeGreaterThan(0);
          for (const link of r.chain.links) {
            if (link.type === "impact") continue;
            expect(isLocation(link.location)).toBe(true);
          }
        }
      });

      it(`${name} → every VerificationStep.target is a structured Location`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          const steps = r.chain.verification_steps ?? [];
          expect(steps.length).toBeGreaterThanOrEqual(2);
          for (const step of steps) {
            expect(isLocation(step.target)).toBe(true);
          }
        }
      });

      it(`${name} → confidence capped at 0.90`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.9);
          expect(r.chain.confidence).toBeGreaterThan(0.1);
        }
      });

      it(`${name} → cites OWASP-ASI09 as primary threat reference`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("OWASP-ASI09");
        }
      });
    }
  });
});
