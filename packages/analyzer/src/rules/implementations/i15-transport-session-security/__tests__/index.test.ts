import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { TransportSessionSecurityRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "__fixtures__");
const rule = new TransportSessionSecurityRule();

function ctxFromSource(name: string): AnalysisContext {
  return {
    server: { id: "i15", name: "i15", description: null, github_url: null },
    tools: [],
    source_code: readFileSync(join(FIX, name), "utf8"),
    dependencies: [],
    connection_metadata: null,
  };
}

describe("I15 — fires", () => {
  it("Math.random session", () => {
    const r = rule.analyze(ctxFromSource("true-positive-01-math-random.ts"));
    expect(r.length).toBeGreaterThanOrEqual(1);
    expect(r[0].severity).toBe("high");
    expect(r[0].chain.threat_reference?.id).toBe("CVE-2025-6515");
  });
  it("insecure cookie flags", () => {
    const r = rule.analyze(ctxFromSource("true-positive-02-insecure-cookie.ts"));
    expect(r.length).toBeGreaterThanOrEqual(1);
  });
});

describe("I15 — does not fire", () => {
  it("crypto.randomUUID session", () => {
    const r = rule.analyze(ctxFromSource("true-negative-01-crypto-random.ts"));
    expect(r.length).toBe(0);
  });
  it("hardened cookie", () => {
    const r = rule.analyze(ctxFromSource("true-negative-02-hardened-cookie.ts"));
    expect(r.length).toBe(0);
  });
});

describe("I15 — evidence integrity", () => {
  it("structured Locations; cap 0.85", () => {
    const r = rule.analyze(ctxFromSource("true-positive-01-math-random.ts"));
    for (const res of r) {
      for (const link of res.chain.links) {
        if (link.type === "impact") continue;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        expect(isLocation((link as any).location)).toBe(true);
      }
      for (const step of res.chain.verification_steps ?? []) {
        expect(isLocation(step.target)).toBe(true);
      }
      expect(res.chain.confidence).toBeLessThanOrEqual(0.85);
    }
  });
});
