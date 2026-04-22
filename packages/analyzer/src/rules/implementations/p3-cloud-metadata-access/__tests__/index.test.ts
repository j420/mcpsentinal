/**
 * P3 v2 — functional + chain-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { CloudMetadataAccessRule } from "../index.js";
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

const rule = new CloudMetadataAccessRule();

describe("P3 — Cloud Metadata Service Access (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags AWS IMDS IPv4 endpoint in source code", () => {
      const { file, text } = loadFixture("true-positive-01-aws-imds.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].rule_id).toBe("P3");
      const src = results[0].chain.links.find((l) => l.type === "source");
      expect(src && src.type === "source" && src.observed).toContain("169.254.169.254");
    });

    it("flags GCP metadata.google.internal hostname (lethal edge #2)", () => {
      const { file, text } = loadFixture("true-positive-02-gcp-hostname.py");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const gcp = results.find((r) => {
        const variantFactor = r.chain.confidence_factors.find((f) => f.factor === "endpoint_variant");
        return variantFactor?.rationale.includes("gcp-hostname");
      });
      expect(gcp).toBeDefined();
    });

    it("flags IMDSv2 HttpPutResponseHopLimit=2 (lethal edge #5)", () => {
      const { file, text } = loadFixture("true-positive-03-hop-limit.yaml");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const hopHit = results.find((r) => {
        const variantFactor = r.chain.confidence_factors.find((f) => f.factor === "endpoint_variant");
        return variantFactor?.rationale.toLowerCase().includes("hop-limit");
      });
      expect(hopHit).toBeDefined();
    });
  });

  describe("does not fire (true negatives)", () => {
    it("does not fire when endpoint is paired with deny / block tokens", () => {
      const { file, text } = loadFixture("true-negative-01-block-rule.yaml");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("does not fire on ordinary application code without metadata references", () => {
      const { file, text } = loadFixture("true-negative-02-ordinary-code.ts");
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
});
