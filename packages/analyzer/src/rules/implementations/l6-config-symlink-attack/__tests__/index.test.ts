/**
 * L6 v2 — Config Directory Symlink Attack: functional + chain-integrity tests.
 *
 * Covers lethal edge cases from the CHARTER:
 *   - Symlink-to-sensitive-target creation (TP-01)
 *   - Unguarded-read (no realpath, no lstat, no NOFOLLOW) (TP-02)
 *   - lstat-followed-by-read race — partial mitigation (TP-03)
 *   - True negative with full mitigation (TN-01)
 *   - True negative with hard-coded paths (TN-02)
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ConfigSymlinkAttackRule } from "../index.js";
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
  const text = readFileSync(join(FIXTURES_DIR, name), "utf8");
  // Mount outside of `__fixtures__` so the test-file filter does not skip it.
  return { file: `src/${name}`, text };
}

const rule = new ConfigSymlinkAttackRule();

describe("L6 — Config Directory Symlink Attack (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags fs.symlinkSync('/etc/passwd', '.claude/...') as symlink-creation-to-sensitive-path", () => {
      const { file, text } = loadFixture("true-positive-01-symlink-to-passwd.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const creation = results
        .flatMap((r) => r.chain.confidence_factors)
        .filter((f) => f.factor === "symlink-creation-to-sensitive-path" && f.adjustment > 0);
      expect(creation.length).toBeGreaterThan(0);
      expect(results[0].severity).toBe("critical");
    });

    it("flags an unguarded readFile on a user-controlled path", () => {
      const { file, text } = loadFixture("true-positive-02-unguarded-read.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const guardFactors = results
        .flatMap((r) => r.chain.confidence_factors)
        .filter((f) => f.factor === "no-symlink-guard-before-read" && f.adjustment > 0);
      expect(guardFactors.length).toBeGreaterThan(0);
    });

    it("flags the lstat-then-read TOCTOU race (partial mitigation)", () => {
      const { file, text } = loadFixture("true-positive-03-lstat-race-then-read.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      // lstatSync IS a guard, so guardPresent=true, but no NOFOLLOW flag.
      // Severity should be "high" (one mitigation present).
      expect(results.some((r) => r.severity === "high")).toBe(true);
      const nofollowFactors = results
        .flatMap((r) => r.chain.confidence_factors)
        .filter((f) => f.factor === "no-nofollow-on-open" && f.adjustment > 0);
      expect(nofollowFactors.length).toBeGreaterThan(0);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("recognises realpath + O_NOFOLLOW as complete mitigation", () => {
      const { file, text } = loadFixture("true-negative-01-realpath-and-nofollow.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("ignores fs.readFileSync on hard-coded literal paths", () => {
      const { file, text } = loadFixture("true-negative-02-hardcoded-paths.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("does not fire on an unrelated source file with no fs calls", () => {
      const ctx = makeContext("src/unrelated.ts", "export const x = 1;");
      expect(rule.analyze(ctx)).toEqual([]);
    });
  });

  describe("chain integrity — v2 contract", () => {
    const tpFixtures = readdirSync(FIXTURES_DIR).filter((n) => n.startsWith("true-positive-"));

    for (const name of tpFixtures) {
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
            expect(
              isLocation(link.location),
              `${name}: ${link.type} location is not a Location — ${JSON.stringify(link.location)}`,
            ).toBe(true);
          }
        }
      });

      it(`${name} → every VerificationStep.target is a structured Location`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          const steps = r.chain.verification_steps ?? [];
          expect(steps.length).toBeGreaterThanOrEqual(3);
          for (const step of steps) {
            expect(
              isLocation(step.target),
              `${name}: step ${step.step_type} target is not a Location`,
            ).toBe(true);
          }
        }
      });

      it(`${name} → confidence within (0.05, 0.85]`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.85);
          // Lower bound is the engine's global clamp floor (0.05).
          // Partial-mitigation findings legitimately score ~0.25 once the
          // -0.3 mitigation-present discount is applied.
          expect(r.chain.confidence).toBeGreaterThan(0.05);
        }
      });

      it(`${name} → cites CVE-2025-53109 as primary threat reference`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("CVE-2025-53109");
        }
      });
    }
  });
});
