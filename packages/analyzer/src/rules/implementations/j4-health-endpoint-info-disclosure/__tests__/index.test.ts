import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { HealthEndpointInfoDisclosureRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "__fixtures__");
const rule = new HealthEndpointInfoDisclosureRule();

function ctx(name: string): AnalysisContext {
  return {
    server: { id: "j4", name: "j4", description: null, github_url: null },
    tools: [],
    source_code: readFileSync(join(FIX, name), "utf8"),
    dependencies: [],
    connection_metadata: null,
  };
}

describe("J4 — fires", () => {
  it("/health/detailed", () => {
    const r = rule.analyze(ctx("true-positive-01-health-detailed.ts"));
    expect(r.length).toBeGreaterThanOrEqual(1);
    expect(r[0].chain.threat_reference?.id).toBe("CVE-2026-29787");
  });
  it("debug + metrics", () => {
    const r = rule.analyze(ctx("true-positive-02-debug-metrics.ts"));
    expect(r.length).toBeGreaterThanOrEqual(2);
  });
});

describe("J4 — does not fire", () => {
  it("/healthz only", () => {
    const r = rule.analyze(ctx("true-negative-01-simple-health.ts"));
    expect(r.length).toBe(0);
  });
  it("no endpoints", () => {
    const r = rule.analyze(ctx("true-negative-02-no-endpoints.ts"));
    expect(r.length).toBe(0);
  });
});

describe("J4 — evidence integrity", () => {
  it("structured Locations; cap 0.92", () => {
    const r = rule.analyze(ctx("true-positive-01-health-detailed.ts"));
    for (const res of r) {
      for (const link of res.chain.links) {
        if (link.type === "impact") continue;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        expect(isLocation((link as any).location)).toBe(true);
      }
      for (const step of res.chain.verification_steps ?? []) {
        expect(isLocation(step.target)).toBe(true);
      }
      expect(res.chain.confidence).toBeLessThanOrEqual(0.92);
    }
  });
});
