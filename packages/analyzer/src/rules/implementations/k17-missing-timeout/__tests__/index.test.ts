/**
 * K17 v2 — functional + chain-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { MissingTimeoutRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function loadFixture(name: string): { file: string; text: string } {
  const file = join(FIXTURES_DIR, name);
  return { file, text: readFileSync(file, "utf8") };
}

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

const rule = new MissingTimeoutRule();

describe("K17 — fires (true positives)", () => {
  it("flags bare fetch without timeout", () => {
    const { file, text } = loadFixture("true-positive-01-fetch-no-timeout.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBe(1);
    expect(results[0].rule_id).toBe("K17");
  });

  it("flags axios.get without timeout", () => {
    const { file, text } = loadFixture("true-positive-02-axios-no-timeout.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBe(1);
  });

  it("flags bare got() without timeout", () => {
    const { file, text } = loadFixture("true-positive-03-got-no-timeout.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBe(1);
  });
});

describe("K17 — does not fire (true negatives)", () => {
  it("accepts axios with per-call timeout", () => {
    const { file, text } = loadFixture("true-negative-01-axios-with-timeout.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });

  it("accepts fetch with AbortController in enclosing scope", () => {
    const { file, text } = loadFixture("true-negative-02-abort-signal-scope.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });

  it("accepts axios.defaults.timeout as file-level global", () => {
    const { file, text } = loadFixture("true-negative-03-axios-global-defaults.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });

  it("accepts got.extend({ timeout }) factory mitigation", () => {
    const { file, text } = loadFixture("true-negative-04-got-extend-factory.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });

  it("skips a structurally-identified test file", () => {
    const { file, text } = loadFixture("true-negative-05-test-file.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });
});

describe("K17 — circuit-breaker mitigation", () => {
  it("lowers confidence when opossum is in dependencies", () => {
    const { file, text } = loadFixture("true-positive-01-fetch-no-timeout.ts");
    const ctx = makeContext(file, text);
    ctx.dependencies = [
      { name: "opossum", version: "6.0.0", has_known_cve: false, cve_ids: [], last_updated: null },
    ];
    const results = rule.analyze(ctx);
    expect(results.length).toBe(1);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("circuit_breaker_dep_present");
  });
});

describe("K17 — v2 chain-integrity contract", () => {
  const fixtureNames = readdirSync(FIXTURES_DIR).filter((n) => n.startsWith("true-positive-"));

  for (const name of fixtureNames) {
    it(`${name} → every evidence link has a structured Location`, () => {
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

    it(`${name} → confidence capped at 0.88, floored above 0.30`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.88);
        expect(r.chain.confidence).toBeGreaterThan(0.3);
      }
    });

    it(`${name} → threat reference cites OWASP-ASI08`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      for (const r of results) {
        expect(r.chain.threat_reference?.id).toBe("OWASP-ASI08");
      }
    });
  }
});
