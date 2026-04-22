/**
 * O6 v2 unit tests — functional coverage + chain-integrity assertions.
 *
 * Edge cases covered (mirroring CHARTER.md lethal_edge_cases):
 *   - TP-01 /health/detailed-style os + process emit in res.json(...)
 *   - TP-02 catch-block-return with err.stack / err.path / syscall
 *   - TP-03 throw new Error carrying DB connection-string surface
 *   - TP-04 auth-branch divergence (auth-gated leak still flagged,
 *           auth_gated_branch_headroom factor applies)
 *   - TN-01 generic "Internal server error" response
 *   - TN-02 fingerprint surface flows into logger only, never response
 *   - TN-03 response uses validated caller input exclusively
 *
 * Chain-integrity assertions:
 *   - every non-impact link carries a structured Location (isLocation)
 *   - every VerificationStep.target is a Location
 *   - confidence is capped at 0.82 (CHARTER)
 *   - chain cites CVE-2026-29787 as threat_reference
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { O6Rule } from "../index.js";
import { gatherO6 } from "../gather.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function loadFixture(name: string): AnalysisContext {
  const file = join(FIXTURES_DIR, name);
  const text = readFileSync(file, "utf8");
  return {
    server: { id: "o6-test", name: "o6-test", description: null, github_url: null },
    tools: [],
    source_code: text,
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new O6Rule();

describe("O6 — True Positives", () => {
  it("TP-01 /health/detailed emits os.hostname + process.version + os.cpus in res.json", () => {
    const ctx = loadFixture("true-positive-01-health-detailed-os.ts");
    const results = rule.analyze(ctx);
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0].severity).toBe("high");
    expect(results[0].owasp_category).toBe("MCP04-data-exfiltration");
    const sites = gatherO6(ctx).sites;
    expect(sites.some((s) => s.responseShape === "response-emitter-call")).toBe(true);
    expect(sites.some((s) => s.kind === "os" || s.kind === "process")).toBe(true);
  });

  it("TP-02 catch-block-return with err.stack + err.path fires", () => {
    const ctx = loadFixture("true-positive-02-catch-returns-stack.ts");
    const results = rule.analyze(ctx);
    expect(results.length).toBeGreaterThanOrEqual(1);
    const sites = gatherO6(ctx).sites;
    expect(sites.some((s) => s.responseShape === "catch-block-return")).toBe(true);
    expect(sites.some((s) => s.kind === "error-field")).toBe(true);
  });

  it("TP-03 throw new Error carrying DB connectionString/driver/dialect fires", () => {
    const ctx = loadFixture("true-positive-03-throw-error-with-db.ts");
    const results = rule.analyze(ctx);
    expect(results.length).toBeGreaterThanOrEqual(1);
    const sites = gatherO6(ctx).sites;
    expect(sites.some((s) => s.responseShape === "throw-error")).toBe(true);
    expect(sites.some((s) => s.kind === "db")).toBe(true);
  });

  it("TP-04 auth-gated branch still flagged (auth headroom factor applied)", () => {
    const ctx = loadFixture("true-positive-04-auth-branch-leak.ts");
    const results = rule.analyze(ctx);
    expect(results.length).toBeGreaterThanOrEqual(1);
    const factorNames = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factorNames).toContain("auth_gated_branch_headroom");
  });
});

describe("O6 — True Negatives", () => {
  it("TN-01 generic 'Internal server error' response → 0 findings", () => {
    expect(rule.analyze(loadFixture("true-negative-01-generic-error.ts")).length).toBe(0);
  });

  it("TN-02 fingerprint surface flows only into logger, never into response → 0 findings", () => {
    expect(rule.analyze(loadFixture("true-negative-02-logs-only.ts")).length).toBe(0);
  });

  it("TN-03 response uses validated caller input only → 0 findings", () => {
    expect(rule.analyze(loadFixture("true-negative-03-validated-input.ts")).length).toBe(0);
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

describe("O6 — Chain integrity", () => {
  const TP_NAMES = [
    "true-positive-01-health-detailed-os.ts",
    "true-positive-02-catch-returns-stack.ts",
    "true-positive-03-throw-error-with-db.ts",
    "true-positive-04-auth-branch-leak.ts",
  ];

  for (const name of TP_NAMES) {
    it(`${name} → every non-impact link has a structured Location`, () => {
      const results = rule.analyze(loadFixture(name));
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        for (const link of r.chain.links) {
          if (link.type === "impact") continue;
          expect(
            isLocation(link.location),
            `${name} ${link.type} link location must be a structured Location`,
          ).toBe(true);
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

    it(`${name} → confidence capped at 0.82`, () => {
      const results = rule.analyze(loadFixture(name));
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.82);
        expect(r.chain.confidence).toBeGreaterThan(0.1);
      }
    });

    it(`${name} → cites CVE-2026-29787 as primary threat reference`, () => {
      const results = rule.analyze(loadFixture(name));
      for (const r of results) {
        expect(r.chain.threat_reference?.id).toBe("CVE-2026-29787");
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
