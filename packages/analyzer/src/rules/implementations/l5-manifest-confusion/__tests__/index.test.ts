/**
 * L5 v2 — structural manifest-confusion tests.
 *
 * Coverage goals:
 *   - Each lethal edge case in the CHARTER has a matching test assertion;
 *   - true-positive fixtures produce ≥1 L5 finding;
 *   - bin-shadow / bin-hidden / exports-divergence primitives ALSO emit
 *     an L14 companion finding in the same RuleResult list;
 *   - true-negative fixtures produce zero findings;
 *   - every link carries a structured Location;
 *   - every VerificationStep.target is a Location;
 *   - confidence in (0.30, 0.85].
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ManifestConfusionRule } from "../index.js";
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

/**
 * makeJsonContext — feeds a raw package.json file path through
 * source_files so the gather.ts JSON-parse path is exercised.
 */
function makeJsonContext(path: string, json: string): AnalysisContext {
  return {
    server: { id: "srv-1", name: "test-server", description: null, github_url: null },
    tools: [],
    source_code: null,
    source_files: new Map([[path, json]]),
    dependencies: [],
    connection_metadata: null,
  };
}

function loadFixture(name: string): { file: string; text: string } {
  const file = join(FIXTURES_DIR, name);
  return { file, text: readFileSync(file, "utf8") };
}

const rule = new ManifestConfusionRule();

describe("L5 — Package Manifest Confusion (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags prepublish manifest mutation alongside a build tool", () => {
      const { file, text } = loadFixture("true-positive-01-prepublish-mutation.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const l5 = results.filter((r) => r.rule_id === "L5");
      expect(l5.length).toBeGreaterThan(0);
      // No L14 companion for this primitive (manifest mutation is not an entry-point mismatch).
      const l14 = results.filter((r) => r.rule_id === "L14");
      expect(l14.length).toBe(0);
    });

    it("flags bin-field system shadow AND hidden-target; emits L14 companions", () => {
      const { file, text } = loadFixture("true-positive-02-bin-shadow.ts");
      const results = rule.analyze(makeContext(file, text));
      const l5 = results.filter((r) => r.rule_id === "L5");
      const l14 = results.filter((r) => r.rule_id === "L14");
      // Two primitives (git shadow + hidden target) → two L5 + two L14 findings.
      expect(l5.length).toBeGreaterThanOrEqual(2);
      expect(l14.length).toBeGreaterThanOrEqual(2);
    });

    it("flags conditional exports divergence with payload filename; emits L14 companion", () => {
      const { file, text } = loadFixture("true-positive-03-exports-divergence.ts");
      const results = rule.analyze(makeContext(file, text));
      const kinds = new Set(results.map((r) => r.rule_id));
      expect(kinds.has("L5")).toBe(true);
      expect(kinds.has("L14")).toBe(true);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("accepts a clean manifest with provenance and equivalent exports", () => {
      const { file, text } = loadFixture("true-negative-01-clean-manifest.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("accepts a prepublish script that runs build tools but never mentions package.json", () => {
      const { file, text } = loadFixture("true-negative-02-build-only-prepublish.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });
  });

  describe("package.json file path (not just embedded literal)", () => {
    it("flags prepublish mutation when the manifest is an actual package.json file", () => {
      const pkg = JSON.stringify({
        name: "p",
        scripts: { prepublish: "sed -i s/a/b/ package.json" },
      });
      const results = rule.analyze(makeJsonContext("package.json", pkg));
      expect(results.some((r) => r.rule_id === "L5")).toBe(true);
    });

    it("skips a nested node_modules/** package.json", () => {
      const pkg = JSON.stringify({
        name: "p",
        scripts: { prepublish: "sed -i s/a/b/ package.json" },
      });
      const results = rule.analyze(makeJsonContext("node_modules/foo/package.json", pkg));
      expect(results).toEqual([]);
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
          const steps = r.chain.verification_steps ?? [];
          expect(steps.length).toBeGreaterThan(0);
          for (const step of steps) {
            expect(isLocation(step.target)).toBe(true);
          }
        }
      });

      it(`${name} → confidence in (0.30, 0.85]`, () => {
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
