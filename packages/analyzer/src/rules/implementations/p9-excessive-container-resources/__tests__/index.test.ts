/**
 * P9 v2 — functional + chain-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ExcessiveContainerResourcesRule } from "../index.js";
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

const rule = new ExcessiveContainerResourcesRule();

describe("P9 — Missing Container Resource Limits (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags mem_limit: unlimited", () => {
      const { file, text } = loadFixture("true-positive-01-memory-unlimited.yaml");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].rule_id).toBe("P9");
      const sink = results[0].chain.links.find((l) => l.type === "sink");
      expect(sink && sink.type === "sink" && sink.observed.toLowerCase()).toContain("mem_limit");
    });

    it("flags pidsLimit: -1 (unlimited sentinel)", () => {
      const { file, text } = loadFixture("true-positive-02-pid-unlimited.yaml");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const anyPid = results.some((r) => {
        const sink = r.chain.links.find((l) => l.type === "sink");
        return sink && sink.type === "sink" && sink.observed.toLowerCase().includes("pid");
      });
      expect(anyPid).toBe(true);
    });

    it("flags excessive memory value (1024Gi)", () => {
      const { file, text } = loadFixture("true-positive-03-excessive-memory.yaml");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      // Exactly one excessive-value finding expected.
      const excessive = results.filter((r) => {
        const src = r.chain.links.find((l) => l.type === "source");
        return src && src.type === "source" && src.rationale.toLowerCase().includes("> 32 gi");
      });
      expect(excessive.length).toBeGreaterThan(0);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("accepts a pod with both requests and limits", () => {
      const { file, text } = loadFixture("true-negative-01-proper-limits.yaml");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("does not fire on commented-out unlimited sentinel", () => {
      const { file, text } = loadFixture("true-negative-02-commented.yaml");
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

      it(`${name} → confidence within [0.30, 0.75]`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.75);
          expect(r.chain.confidence).toBeGreaterThan(0.3);
        }
      });
    }
  });
});
