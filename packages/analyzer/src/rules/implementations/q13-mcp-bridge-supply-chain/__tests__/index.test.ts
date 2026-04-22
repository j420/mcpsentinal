/**
 * Q13 v2 unit tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { McpBridgeSupplyChainRule } from "../index.js";
import { gatherQ13 } from "../gather.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation, type Location } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function loadFixture(name: string): AnalysisContext {
  const file = join(FIXTURES_DIR, name);
  const text = readFileSync(file, "utf8");
  return {
    server: { id: "q13-test", name: "q13-test", description: null, github_url: null },
    tools: [],
    source_code: text,
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new McpBridgeSupplyChainRule();

describe("Q13 — True Positives", () => {
  it("TP-01 unpinned npx mcp-remote literal fires", () => {
    const ctx = loadFixture("true-positive-01-npx-unpinned.ts");
    const r = rule.analyze(ctx);
    expect(r.length).toBeGreaterThanOrEqual(1);
    expect(r[0].severity).toBe("critical");
    const sites = gatherQ13(ctx).sites;
    expect(sites.some((s) => s.kind === "shell-literal")).toBe(true);
  });

  it("TP-02 spawn('npx', ['mcp-proxy']) fires", () => {
    const ctx = loadFixture("true-positive-02-spawn-args.ts");
    const r = rule.analyze(ctx);
    expect(r.length).toBeGreaterThanOrEqual(1);
    const sites = gatherQ13(ctx).sites;
    expect(sites.some((s) => s.kind === "child-process-args")).toBe(true);
  });

  it("TP-03 manifest with '^1.0.0' for mcp-remote fires", () => {
    const ctx = loadFixture("true-positive-03-manifest-caret.ts");
    const r = rule.analyze(ctx);
    expect(r.length).toBeGreaterThanOrEqual(1);
    const sites = gatherQ13(ctx).sites;
    expect(sites.some((s) => s.kind === "manifest-range")).toBe(true);
  });
});

describe("Q13 — True Negatives", () => {
  it("TN-01 pinned npx mcp-remote@1.2.3 → 0 findings", () => {
    expect(rule.analyze(loadFixture("true-negative-01-pinned-npx.ts")).length).toBe(0);
  });

  it("TN-02 exact-version manifest → 0 findings", () => {
    expect(rule.analyze(loadFixture("true-negative-02-pinned-manifest.ts")).length).toBe(0);
  });
});

describe("Q13 — Chain integrity", () => {
  it("every chain link carries a structured source Location", () => {
    const ctx = loadFixture("true-positive-01-npx-unpinned.ts");
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

  it("confidence is capped at 0.80", () => {
    const ctx = loadFixture("true-positive-02-spawn-args.ts");
    const r = rule.analyze(ctx);
    expect(r[0].chain.confidence).toBeLessThanOrEqual(0.80);
  });

  it("chain includes source + propagation + sink + impact", () => {
    const r = rule.analyze(loadFixture("true-positive-01-npx-unpinned.ts"));
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
