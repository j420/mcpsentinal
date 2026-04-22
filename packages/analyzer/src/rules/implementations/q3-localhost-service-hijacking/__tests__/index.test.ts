/**
 * Q3 v2 unit tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { LocalhostHijackingRule } from "../index.js";
import { gatherQ3 } from "../gather.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation, type Location } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function loadFixture(name: string): AnalysisContext {
  const file = join(FIXTURES_DIR, name);
  const text = readFileSync(file, "utf8");
  return {
    server: { id: "q3-test", name: "q3-test", description: null, github_url: null },
    tools: [],
    source_code: text,
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new LocalhostHijackingRule();

describe("Q3 — True Positives", () => {
  it("TP-01 listen on 127.0.0.1 fires", () => {
    const ctx = loadFixture("true-positive-01-listen-localhost.ts");
    const r = rule.analyze(ctx);
    expect(r.length).toBeGreaterThanOrEqual(1);
    expect(r[0].severity).toBe("critical");
  });

  it("TP-02 bind on 0.0.0.0 fires and receiver mentions MCP", () => {
    const ctx = loadFixture("true-positive-02-bind-all-interfaces.ts");
    const r = rule.analyze(ctx);
    expect(r.length).toBeGreaterThanOrEqual(1);
    const sites = gatherQ3(ctx).sites;
    expect(sites.some((s) => s.host === "0.0.0.0")).toBe(true);
    expect(sites.some((s) => s.mcpTokenOnReceiver)).toBe(true);
  });

  it('TP-03 listen on "localhost" string fires', () => {
    const ctx = loadFixture("true-positive-03-localhost-hostname.ts");
    const r = rule.analyze(ctx);
    expect(r.length).toBeGreaterThanOrEqual(1);
  });
});

describe("Q3 — True Negatives", () => {
  it("TN-01 no network binding → 0 findings (honest refusal)", () => {
    const ctx = loadFixture("true-negative-01-no-network.ts");
    const g = gatherQ3(ctx);
    expect(g.noNetworkBinding).toBe(true);
    expect(rule.analyze(ctx).length).toBe(0);
  });

  it("TN-02 localhost bind with bearer auth in scope → 0 findings", () => {
    expect(rule.analyze(loadFixture("true-negative-02-authenticated.ts")).length).toBe(0);
  });
});

describe("Q3 — Chain integrity", () => {
  it("every chain link carries a structured source Location", () => {
    const ctx = loadFixture("true-positive-01-listen-localhost.ts");
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

  it("confidence is capped at 0.75", () => {
    const ctx = loadFixture("true-positive-02-bind-all-interfaces.ts");
    const r = rule.analyze(ctx);
    expect(r[0].chain.confidence).toBeLessThanOrEqual(0.75);
  });

  it("chain includes source + propagation + sink + impact", () => {
    const r = rule.analyze(loadFixture("true-positive-01-listen-localhost.ts"));
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
