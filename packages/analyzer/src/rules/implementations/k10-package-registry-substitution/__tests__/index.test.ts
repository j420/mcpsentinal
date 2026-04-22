/**
 * K10 v2 — registry substitution tests.
 *
 * Fixtures exercise:
 *   - .npmrc with an untrusted external URL (TP; high severity)
 *   - pip.conf with an attacker-PyPI URL (TP; high severity)
 *   - .npmrc with plain HTTP to a non-trusted host (TP; amplifier factor)
 *   - .npmrc with the official npm registry (TN; classified as trusted)
 *   - scoped enterprise mirror + official global registry (TN for global,
 *     either no finding or a medium informational advisory for the scoped URL)
 *
 * Fixtures are .txt files so they can be written to a `.npmrc` /
 * `pip.conf` virtual path at test time.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { PackageRegistrySubstitutionRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function makeConfigContext(virtualPath: string, text: string): AnalysisContext {
  return {
    server: { id: "srv-1", name: "test-server", description: null, github_url: null },
    tools: [],
    source_code: null,
    source_files: new Map([[virtualPath, text]]),
    dependencies: [],
    connection_metadata: null,
  };
}

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, name), "utf8");
}

const rule = new PackageRegistrySubstitutionRule();

describe("K10 — Package Registry Substitution (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags an untrusted .npmrc registry URL", () => {
      const text = loadFixture("true-positive-01-npmrc-evil.txt");
      const results = rule.analyze(makeConfigContext(".npmrc", text));
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].rule_id).toBe("K10");
      expect(results[0].severity).toBe("high");
    });

    it("flags an untrusted pip.conf index-url", () => {
      const text = loadFixture("true-positive-02-pip-evil.txt");
      const results = rule.analyze(makeConfigContext("pip.conf", text));
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].severity).toBe("high");
    });

    it("flags plain HTTP on a non-trusted host and records the downgrade factor", () => {
      const text = loadFixture("true-positive-03-http-downgrade.txt");
      const results = rule.analyze(makeConfigContext(".npmrc", text));
      expect(results.length).toBeGreaterThan(0);
      const factors = results.flatMap((r) => r.chain.confidence_factors.map((f) => f.factor));
      expect(factors).toContain("http_transport_amplifier");
    });

    it("flags process.env.NPM_CONFIG_REGISTRY = '...' in source code", () => {
      const source = `
        process.env.NPM_CONFIG_REGISTRY = "https://evil.example.com/npm/";
      `;
      const results = rule.analyze({
        server: { id: "s", name: "t", description: null, github_url: null },
        tools: [],
        source_code: source,
        source_files: new Map([["setup.ts", source]]),
        dependencies: [],
        connection_metadata: null,
      });
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].severity).toBe("high");
    });
  });

  describe("does not fire (true negatives)", () => {
    it("accepts an official registry URL", () => {
      const text = loadFixture("true-negative-01-npmrc-official.txt");
      expect(rule.analyze(makeConfigContext(".npmrc", text))).toEqual([]);
    });

    it("accepts a scoped enterprise mirror alongside the official global registry", () => {
      const text = loadFixture("true-negative-02-scoped-mirror.txt");
      const results = rule.analyze(makeConfigContext(".npmrc", text));
      // The scoped URL is enterprise-shaped → either no finding or
      // a medium informational advisory. It must NOT be high severity.
      for (const r of results) {
        expect(r.severity).not.toBe("high");
      }
    });
  });

  describe("chain integrity — v2 contract", () => {
    const tps = readdirSync(FIXTURES_DIR).filter((n) => n.startsWith("true-positive-"));
    for (const name of tps) {
      it(`${name} → every link has a structured Location`, () => {
        const text = loadFixture(name);
        const virtualPath = name.includes("pip") ? "pip.conf" : ".npmrc";
        const results = rule.analyze(makeConfigContext(virtualPath, text));
        expect(results.length).toBeGreaterThan(0);
        for (const r of results) {
          for (const link of r.chain.links) {
            if (link.type === "impact") continue;
            expect(isLocation(link.location)).toBe(true);
          }
        }
      });

      it(`${name} → every VerificationStep.target is a Location`, () => {
        const text = loadFixture(name);
        const virtualPath = name.includes("pip") ? "pip.conf" : ".npmrc";
        const results = rule.analyze(makeConfigContext(virtualPath, text));
        for (const r of results) {
          const steps = r.chain.verification_steps ?? [];
          expect(steps.length).toBeGreaterThan(0);
          for (const step of steps) {
            expect(isLocation(step.target)).toBe(true);
          }
        }
      });

      it(`${name} → confidence in (0.30, 0.80]`, () => {
        const text = loadFixture(name);
        const virtualPath = name.includes("pip") ? "pip.conf" : ".npmrc";
        const results = rule.analyze(makeConfigContext(virtualPath, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.8);
          expect(r.chain.confidence).toBeGreaterThan(0.3);
        }
      });
    }
  });
});
