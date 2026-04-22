/**
 * O8 v2 unit tests — functional coverage + chain-integrity assertions.
 *
 * Edge cases covered (mirroring CHARTER.md lethal_edge_cases):
 *   - TP-01 setTimeout(cb, secret.charCodeAt(i)) — per-byte delay
 *   - TP-02 await sleep(token[i]) — per-char latency encoding
 *   - TP-03 res.setHeader("Retry-After", secret.charCodeAt(i))
 *   - TP-04 progress-interval modulation around variable sleep (N15 cross-ref)
 *   - TN-01 fixed numeric-literal delay
 *   - TN-02 exponential backoff using counter identifier (retryCount)
 *   - TN-03 honest-refusal: no timing primitive in source
 *
 * Chain-integrity assertions:
 *   - every non-impact link carries a structured Location
 *   - every VerificationStep.target is a Location
 *   - confidence capped at 0.72 (CHARTER)
 *   - chain cites MITRE-ATLAS-AML-T0057
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { O8Rule } from "../index.js";
import { gatherO8 } from "../gather.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function loadFixture(name: string): AnalysisContext {
  const file = join(FIXTURES_DIR, name);
  const text = readFileSync(file, "utf8");
  return {
    server: { id: "o8-test", name: "o8-test", description: null, github_url: null },
    tools: [],
    source_code: text,
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new O8Rule();

describe("O8 — True Positives", () => {
  it("TP-01 setTimeout(cb, secret.charCodeAt(i)) fires", () => {
    const ctx = loadFixture("true-positive-01-secret-charcode.ts");
    const results = rule.analyze(ctx);
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0].severity).toBe("high");
    const sites = gatherO8(ctx).sites;
    expect(sites.some((s) => s.shape === "set-timeout-call")).toBe(true);
    expect(sites.some((s) => s.matchedDataHint === "secret")).toBe(true);
  });

  it("TP-02 await sleep(token[i]) fires", () => {
    const ctx = loadFixture("true-positive-02-sleep-token.ts");
    const results = rule.analyze(ctx);
    expect(results.length).toBeGreaterThanOrEqual(1);
    const sites = gatherO8(ctx).sites;
    expect(sites.some((s) => s.shape === "sleep-call")).toBe(true);
    expect(sites.some((s) => s.matchedDataHint === "token")).toBe(true);
  });

  it("TP-03 Retry-After header modulation fires", () => {
    const ctx = loadFixture("true-positive-03-retry-after-modulation.ts");
    const results = rule.analyze(ctx);
    expect(results.length).toBeGreaterThanOrEqual(1);
    const sites = gatherO8(ctx).sites;
    expect(sites.some((s) => s.shape === "retry-after-header")).toBe(true);
  });

  it("TP-04 progress-notification interval modulation fires", () => {
    const ctx = loadFixture("true-positive-04-progress-interval.ts");
    const results = rule.analyze(ctx);
    expect(results.length).toBeGreaterThanOrEqual(1);
    const sites = gatherO8(ctx).sites;
    expect(sites.some((s) => s.shape === "progress-interval-modulation")).toBe(true);
  });
});

describe("O8 — True Negatives", () => {
  it("TN-01 fixed setTimeout(cb, 1000) → 0 findings", () => {
    expect(rule.analyze(loadFixture("true-negative-01-fixed-rate-limit.ts")).length).toBe(0);
  });

  it("TN-02 exponential backoff (retryCount) → 0 findings", () => {
    expect(rule.analyze(loadFixture("true-negative-02-exponential-backoff.ts")).length).toBe(0);
  });

  it("TN-03 honest-refusal: no timing primitive → 0 findings", () => {
    const ctx = loadFixture("true-negative-03-no-timing-primitive.ts");
    const gathered = gatherO8(ctx);
    expect(gathered.hasTimingPrimitive).toBe(false);
    expect(rule.analyze(ctx).length).toBe(0);
  });

  it("returns [] when source_code is null", () => {
    expect(
      rule.analyze({
        server: { id: "e", name: "e", description: null, github_url: null },
        tools: [],
        source_code: null,
        dependencies: [],
        connection_metadata: null,
      }).length,
    ).toBe(0);
  });
});

describe("O8 — Chain integrity", () => {
  const TP_NAMES = [
    "true-positive-01-secret-charcode.ts",
    "true-positive-02-sleep-token.ts",
    "true-positive-03-retry-after-modulation.ts",
    "true-positive-04-progress-interval.ts",
  ];

  for (const name of TP_NAMES) {
    it(`${name} → every non-impact link has a structured Location`, () => {
      const results = rule.analyze(loadFixture(name));
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        for (const link of r.chain.links) {
          if (link.type === "impact") continue;
          expect(isLocation(link.location)).toBe(true);
        }
      }
    });

    it(`${name} → every VerificationStep.target is a Location`, () => {
      const results = rule.analyze(loadFixture(name));
      for (const r of results) {
        const steps = r.chain.verification_steps ?? [];
        expect(steps.length).toBeGreaterThan(0);
        for (const step of steps) {
          expect(isLocation(step.target)).toBe(true);
        }
      }
    });

    it(`${name} → confidence capped at 0.72`, () => {
      const results = rule.analyze(loadFixture(name));
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.72);
        expect(r.chain.confidence).toBeGreaterThan(0.1);
      }
    });

    it(`${name} → cites MITRE-ATLAS-AML-T0057`, () => {
      const results = rule.analyze(loadFixture(name));
      for (const r of results) {
        expect(r.chain.threat_reference?.id).toBe("MITRE-ATLAS-AML-T0057");
      }
    });

    it(`${name} → chain contains source + propagation + sink + impact`, () => {
      const results = rule.analyze(loadFixture(name));
      for (const r of results) {
        const types = new Set(r.chain.links.map((l) => l.type));
        expect(types.has("source")).toBe(true);
        expect(types.has("propagation")).toBe(true);
        expect(types.has("sink")).toBe(true);
        expect(types.has("impact")).toBe(true);
      }
    });
  }
});
