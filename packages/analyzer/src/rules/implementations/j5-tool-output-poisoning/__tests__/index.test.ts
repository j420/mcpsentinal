import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ToolOutputPoisoningRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "__fixtures__");
const rule = new ToolOutputPoisoningRule();

function ctx(name: string): AnalysisContext {
  return {
    server: { id: "j5", name: "j5", description: null, github_url: null },
    tools: [],
    source_code: readFileSync(join(FIX, name), "utf8"),
    dependencies: [],
    connection_metadata: null,
  };
}

describe("J5 — fires", () => {
  it("error says read .ssh", () => {
    const r = rule.analyze(ctx("true-positive-01-error-ssh.ts"));
    expect(r.length).toBeGreaterThanOrEqual(1);
    expect(r[0].severity).toBe("critical");
  });
  it("return + please + execute", () => {
    const r = rule.analyze(ctx("true-positive-02-return-please-execute.ts"));
    expect(r.length).toBeGreaterThanOrEqual(1);
  });
});

describe("J5 — does not fire", () => {
  it("clean error", () => {
    const r = rule.analyze(ctx("true-negative-01-clean-error.ts"));
    expect(r.length).toBe(0);
  });
  it("simple ok return", () => {
    const r = rule.analyze(ctx("true-negative-02-simple-return.ts"));
    expect(r.length).toBe(0);
  });
});

describe("J5 — evidence integrity", () => {
  it("structured Locations; cap 0.82", () => {
    const r = rule.analyze(ctx("true-positive-01-error-ssh.ts"));
    for (const res of r) {
      for (const link of res.chain.links) {
        if (link.type === "impact") continue;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        expect(isLocation((link as any).location)).toBe(true);
      }
      for (const step of res.chain.verification_steps ?? []) {
        expect(isLocation(step.target)).toBe(true);
      }
      expect(res.chain.confidence).toBeLessThanOrEqual(0.82);
    }
  });
});
