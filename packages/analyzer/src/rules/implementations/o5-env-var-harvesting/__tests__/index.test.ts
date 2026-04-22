/**
 * O5 v2 unit tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { EnvVarHarvestingRule } from "../index.js";
import { gatherO5 } from "../gather.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation, type Location } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function loadFixture(name: string): AnalysisContext {
  const file = join(FIXTURES_DIR, name);
  const text = readFileSync(file, "utf8");
  return {
    server: { id: "o5-test", name: "o5-test", description: null, github_url: null },
    tools: [],
    source_code: text,
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new EnvVarHarvestingRule();

describe("O5 — True Positives", () => {
  it("TP-01 Object.keys(process.env) fires (object-keys-call)", () => {
    const ctx = loadFixture("true-positive-01-object-keys-process-env.ts");
    const r = rule.analyze(ctx);
    expect(r.length).toBeGreaterThanOrEqual(1);
    expect(r[0].severity).toBe("critical");
    const sites = gatherO5(ctx).sites;
    expect(sites.some((s) => s.kind === "object-keys-call")).toBe(true);
    expect(sites.some((s) => s.receiver === "process.env")).toBe(true);
  });

  it("TP-02 JSON.stringify(process.env) fires", () => {
    const ctx = loadFixture("true-positive-02-json-stringify.ts");
    const r = rule.analyze(ctx);
    expect(r.length).toBeGreaterThanOrEqual(1);
    const sites = gatherO5(ctx).sites;
    expect(sites.some((s) => s.kind === "json-stringify")).toBe(true);
  });

  it("TP-03 `{ ...process.env }` object-spread fires", () => {
    const ctx = loadFixture("true-positive-03-spread.ts");
    const r = rule.analyze(ctx);
    expect(r.length).toBeGreaterThanOrEqual(1);
    const sites = gatherO5(ctx).sites;
    expect(sites.some((s) => s.kind === "object-spread")).toBe(true);
  });
});

describe("O5 — True Negatives", () => {
  it("TN-01 single named env var read → 0 findings", () => {
    expect(rule.analyze(loadFixture("true-negative-01-single-var.ts")).length).toBe(0);
  });

  it("TN-02 allowlist-filtered bulk read → 0 findings", () => {
    expect(rule.analyze(loadFixture("true-negative-02-allowlisted.ts")).length).toBe(0);
  });
});

describe("O5 — Chain integrity", () => {
  it("every chain link carries a structured source Location", () => {
    const ctx = loadFixture("true-positive-01-object-keys-process-env.ts");
    const r = rule.analyze(ctx);
    for (const link of r[0].chain.links) {
      if (link.type === "impact") continue;
      expect(isLocation(link.location)).toBe(true);
      if (isLocation(link.location)) {
        expect((link.location as Location).kind).toBe("source");
      }
    }
    for (const step of r[0].chain.verification_steps ?? []) {
      expect(isLocation(step.target)).toBe(true);
    }
  });

  it("confidence is capped at 0.85", () => {
    const ctx = loadFixture("true-positive-02-json-stringify.ts");
    const r = rule.analyze(ctx);
    expect(r[0].chain.confidence).toBeLessThanOrEqual(0.85);
  });

  it("chain includes source + propagation + sink + impact", () => {
    const r = rule.analyze(loadFixture("true-positive-01-object-keys-process-env.ts"));
    const types = new Set(r[0].chain.links.map((l) => l.type));
    expect(types.has("source")).toBe(true);
    expect(types.has("propagation")).toBe(true);
    expect(types.has("sink")).toBe(true);
    expect(types.has("impact")).toBe(true);
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
