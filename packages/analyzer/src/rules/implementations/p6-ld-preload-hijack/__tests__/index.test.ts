/**
 * P6 v2 — functional + chain-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { LDPreloadRule } from "../index.js";
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

const POSITIVE_FIXTURES = [
  "Dockerfile.ld-preload",
  "true-positive-02-ld-so-preload.sh",
  "true-positive-03-dlopen-variable.c",
];

const rule = new LDPreloadRule();

describe("P6 — LD_PRELOAD / Shared Library Hijack (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags LD_PRELOAD env assignment in Dockerfile", () => {
      const { file, text } = loadFixture("Dockerfile.ld-preload");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].rule_id).toBe("P6");
    });

    it("flags /etc/ld.so.preload write (lethal edge #1)", () => {
      const { file, text } = loadFixture("true-positive-02-ld-so-preload.sh");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const scope = results[0].chain.confidence_factors.find((f) => f.factor === "attack_scope");
      expect(scope?.rationale.toLowerCase()).toContain("system-wide");
    });

    it("flags dlopen with variable path (lethal edge #3)", () => {
      const { file, text } = loadFixture("true-positive-03-dlopen-variable.c");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const pathFactor = results[0].chain.confidence_factors.find((f) => f.factor === "variable_path");
      expect(pathFactor?.rationale.toLowerCase()).toContain("attacker-controllable");
    });
  });

  describe("does not fire (true negatives)", () => {
    it("accepts hard-coded dlopen of libssl.so.3", () => {
      const { file, text } = loadFixture("true-negative-01-dlopen-trusted.c");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("does not fire on comment-only mention of /etc/ld.so.preload", () => {
      const { file, text } = loadFixture("true-negative-02-docs-mention.sh");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });
  });

  describe("chain integrity — v2 contract", () => {
    for (const name of POSITIVE_FIXTURES) {
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

      it(`${name} → cites CVE-2010-3856`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("CVE-2010-3856");
        }
      });
    }
  });
});
