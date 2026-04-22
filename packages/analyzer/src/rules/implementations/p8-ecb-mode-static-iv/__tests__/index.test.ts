/**
 * P8 v2 — functional + chain-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { EcbStaticIvRule } from "../index.js";
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

const rule = new EcbStaticIvRule();

describe("P8 — Insecure Cryptographic Mode or Static IV/Nonce (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags ECB as a string literal", () => {
      const { file, text } = loadFixture("true-positive-01-ecb-literal.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].rule_id).toBe("P8");
      const src = results[0].chain.links.find((l) => l.type === "source");
      expect(src && src.type === "source" && src.rationale.toLowerCase()).toContain("ecb");
    });

    it("flags ECB smuggled through a variable binding (edge case #1)", () => {
      const { file, text } = loadFixture("true-positive-02-ecb-via-variable.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const anyEcb = results.some((r) => {
        const src = r.chain.links.find((l) => l.type === "source");
        return src && src.type === "source" && src.rationale.toLowerCase().includes("ecb");
      });
      expect(anyEcb).toBe(true);
    });

    it("flags Buffer.alloc(16) as a zero IV (edge case #2)", () => {
      const { file, text } = loadFixture("true-positive-03-static-iv-buffer-alloc.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const src = results[0].chain.links.find((l) => l.type === "source");
      expect(src && src.type === "source" && src.rationale.toLowerCase()).toContain("iv");
    });

    it("flags Math.random() in a token-generation function (edge case #3)", () => {
      const { file, text } = loadFixture("true-positive-04-math-random-token.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const src = results[0].chain.links.find((l) => l.type === "source");
      expect(src && src.type === "source" && src.rationale.toLowerCase()).toContain("math.random");
    });
  });

  describe("does not fire (true negatives)", () => {
    it("accepts GCM + crypto.randomBytes IV", () => {
      const { file, text } = loadFixture("true-negative-01-gcm-csprng.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("ignores Math.random() in a non-crypto shuffle function", () => {
      const { file, text } = loadFixture("true-negative-02-math-random-non-crypto.ts");
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

      it(`${name} → every VerificationStep.target is a Location`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          for (const step of r.chain.verification_steps ?? []) {
            expect(isLocation(step.target)).toBe(true);
          }
        }
      });

      it(`${name} → confidence within [0.10, 0.80]`, () => {
        // Lower bound 0.10 because the mitigation link adjusts -0.30
        // when a CSPRNG is used elsewhere in the same file — the
        // developer has the correct primitive available but chose the
        // weak path at the flagged line, which is a legitimate
        // compliance finding but at reduced confidence.
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.8);
          expect(r.chain.confidence).toBeGreaterThan(0.1);
        }
      });

      it(`${name} → cites CWE-327`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("CWE-327");
        }
      });
    }
  });
});
