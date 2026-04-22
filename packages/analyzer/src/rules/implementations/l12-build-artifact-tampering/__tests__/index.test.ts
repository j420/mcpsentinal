/**
 * L12 v2 — post-test artifact tamper tests.
 *
 * Fixtures exercise:
 *   - sed against dist/ in a prepublishOnly hook camouflaged by tsc (TP)
 *   - echo >> append in a postbuild hook (TP)
 *   - awk + mv to rewrite a dist/ file in a prepack hook (TP)
 *   - build tools only (TN)
 *   - sed on source directory, not dist/ (TN)
 *
 * Chain integrity: every link has a structured Location; every
 * VerificationStep.target is a Location; confidence in (0.30, 0.85].
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { BuildArtifactTamperingRule } from "../index.js";
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

const rule = new BuildArtifactTamperingRule();

describe("L12 — Build Artifact Tampering (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags sed against dist/ in prepublishOnly camouflaged by tsc", () => {
      const { file, text } = loadFixture("true-positive-01-prepublish-sed.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].rule_id).toBe("L12");
      expect(results[0].severity).toBe("critical");
    });

    it("flags echo >> append in postbuild", () => {
      const { file, text } = loadFixture("true-positive-02-postbuild-append.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
    });

    it("flags awk + mv in prepack", () => {
      const { file, text } = loadFixture("true-positive-03-prepack-awk.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("accepts a build-tool-only pipeline with provenance", () => {
      const { file, text } = loadFixture("true-negative-01-build-only.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("accepts sed targeting src/ (not dist/)", () => {
      const { file, text } = loadFixture("true-negative-02-sed-on-source.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });
  });

  describe("package.json file path (not just embedded literal)", () => {
    it("flags sed against dist/ inside an actual package.json", () => {
      const pkg = JSON.stringify({
        scripts: { postbuild: "sed -i s/a/b/g dist/index.js" },
      });
      const results = rule.analyze(makeJsonContext("package.json", pkg));
      expect(results.some((r) => r.rule_id === "L12")).toBe(true);
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
