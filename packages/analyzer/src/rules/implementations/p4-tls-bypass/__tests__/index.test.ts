/**
 * P4 v2 — functional + chain-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { TLSBypassRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function makeContext(path: string, text: string): AnalysisContext {
  return {
    server: { id: "srv-1", name: "test-server", description: null, github_url: null },
    tools: [],
    source_code: text,
    source_files: new Map([[path, text]]),
    dependencies: [],
    connection_metadata: null,
  };
}

function loadFixture(name: string): { file: string; text: string } {
  const file = join(FIXTURES_DIR, name);
  return { file, text: readFileSync(file, "utf8") };
}

const rule = new TLSBypassRule();

describe("P4 — TLS Certificate Validation Bypass (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags Node.js rejectUnauthorized: false", () => {
      const { file, text } = loadFixture("true-positive-01-node-reject-unauthorized.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].rule_id).toBe("P4");
    });

    it("flags global-scope NODE_TLS_REJECT_UNAUTHORIZED=0 (lethal edge #1)", () => {
      const { file, text } = loadFixture("true-positive-02-node-global-env.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const globalFactor = results[0].chain.confidence_factors.find(
        (f) => f.factor === "global_scope_impact",
      );
      expect(globalFactor?.rationale.toLowerCase()).toContain("global-scope override");
    });

    it("flags Python verify=False with warning-suppression amplifier (lethal edge #3)", () => {
      const { file, text } = loadFixture("true-positive-03-python-verify-false.py");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const verifyFinding = results.find((r) => {
        const variantFactor = r.chain.confidence_factors.find((f) => f.factor === "bypass_variant");
        return variantFactor?.rationale.includes("python-verify-False");
      });
      expect(verifyFinding).toBeDefined();
      const amp = verifyFinding?.chain.confidence_factors.find((f) => f.factor === "amplifier_present");
      expect(amp?.rationale.toLowerCase()).toContain("amplifier present");
    });
  });

  describe("does not fire (true negatives)", () => {
    it("accepts Node.js CA pinning via ca option", () => {
      const { file, text } = loadFixture("true-negative-01-proper-ca.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("accepts Python verify=\"/path/ca.pem\"", () => {
      const { file, text } = loadFixture("true-negative-02-verify-true.py");
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
            expect(isLocation(link.location)).toBe(true);
          }
        }
      });

      it(`${name} → VerificationStep targets are Locations`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          for (const step of r.chain.verification_steps ?? []) {
            expect(isLocation(step.target)).toBe(true);
          }
        }
      });

      it(`${name} → confidence within [0.30, 0.85]`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.85);
          expect(r.chain.confidence).toBeGreaterThan(0.3);
        }
      });
    }
  });
});
