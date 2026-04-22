/**
 * P5 v2 — functional + chain-integrity tests.
 *
 * Note: fixture filenames start with "Dockerfile." so the gatherer's
 * isDockerfilePath() recognises them. We categorise into positives /
 * negatives explicitly rather than via filename prefix.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { SecretsInBuildLayersRule } from "../index.js";
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
  "Dockerfile.arg",
  "Dockerfile.env-copy",
  "Dockerfile.run-inline",
];
const NEGATIVE_FIXTURES = ["Dockerfile.buildkit", "Dockerfile.ordinary"];

const rule = new SecretsInBuildLayersRule();

describe("P5 — Secrets in Container Build Layers (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags ARG API_KEY=<default> (lethal edge #1)", () => {
      const { file, text } = loadFixture("Dockerfile.arg");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].rule_id).toBe("P5");
      const variantFactor = results[0].chain.confidence_factors.find((f) => f.factor === "variant");
      expect(variantFactor?.rationale.toLowerCase()).toContain("arg");
    });

    it("flags ENV DATABASE_URL and COPY .env (lethal edge #2)", () => {
      const { file, text } = loadFixture("Dockerfile.env-copy");
      const results = rule.analyze(makeContext(file, text));
      const envFound = results.some((r) => {
        const f = r.chain.confidence_factors.find((c) => c.factor === "variant");
        return f?.rationale.toLowerCase().includes("env");
      });
      const copyFound = results.some((r) => {
        const f = r.chain.confidence_factors.find((c) => c.factor === "variant");
        return f?.rationale.toLowerCase().includes("copy-file");
      });
      expect(envFound).toBe(true);
      expect(copyFound).toBe(true);
    });

    it("flags RUN NPM_TOKEN=<value> inline assignment (lethal edge #5)", () => {
      const { file, text } = loadFixture("Dockerfile.run-inline");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const runFound = results.some((r) => {
        const f = r.chain.confidence_factors.find((c) => c.factor === "variant");
        return f?.rationale.toLowerCase().includes("run-inline");
      });
      expect(runFound).toBe(true);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("exempts BuildKit --mount=type=secret RUN step (lethal edge #4)", () => {
      const { file, text } = loadFixture("Dockerfile.buildkit");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("does not fire on an ordinary Dockerfile without credential identifiers", () => {
      const { file, text } = loadFixture("Dockerfile.ordinary");
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

      it(`${name} → confidence within [0.30, 0.80]`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.8);
          expect(r.chain.confidence).toBeGreaterThan(0.3);
        }
      });
    }
  });

  it("every negative fixture returns []", () => {
    for (const name of NEGATIVE_FIXTURES) {
      const { file, text } = loadFixture(name);
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    }
  });
});
