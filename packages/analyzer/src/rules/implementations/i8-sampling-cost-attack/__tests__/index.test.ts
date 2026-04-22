import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { SamplingCostAttackRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "__fixtures__");
const rule = new SamplingCostAttackRule();

function ctxFromSource(srcFile: string, samplingDeclared = true): AnalysisContext {
  const source = readFileSync(join(FIX, srcFile), "utf8");
  return {
    server: { id: "i8", name: "i8", description: null, github_url: null },
    tools: [],
    source_code: source,
    dependencies: [],
    connection_metadata: null,
    declared_capabilities: { sampling: samplingDeclared },
  };
}

describe("I8 — fires", () => {
  it("sampling + no controls in source", () => {
    const r = rule.analyze(ctxFromSource("true-positive-01-sampling-no-controls.ts"));
    expect(r.length).toBe(1);
    expect(r[0].severity).toBe("high");
  });
  it("empty sampling handler", () => {
    const r = rule.analyze(ctxFromSource("true-positive-02-minimal.ts"));
    expect(r.length).toBe(1);
  });
  it("informational when source missing", () => {
    const ctx: AnalysisContext = {
      server: { id: "i8", name: "i8", description: null, github_url: null },
      tools: [],
      source_code: null,
      dependencies: [],
      connection_metadata: null,
      declared_capabilities: { sampling: true },
    };
    const r = rule.analyze(ctx);
    expect(r.length).toBe(1);
    expect(r[0].severity).toBe("informational");
  });
});

describe("I8 — does not fire", () => {
  it("max_tokens present in source", () => {
    const r = rule.analyze(ctxFromSource("true-negative-01-with-max-tokens.ts"));
    expect(r.length).toBe(0);
  });
  it("rate_limit + budget present", () => {
    const r = rule.analyze(ctxFromSource("true-negative-02-rate-limited.ts"));
    expect(r.length).toBe(0);
  });
  it("sampling not declared", () => {
    const ctx: AnalysisContext = {
      server: { id: "i8", name: "i8", description: null, github_url: null },
      tools: [],
      source_code: "function f() {}",
      dependencies: [],
      connection_metadata: null,
      declared_capabilities: { sampling: false },
    };
    expect(rule.analyze(ctx).length).toBe(0);
  });
});

describe("I8 — evidence integrity", () => {
  it("structured Locations; cap 0.75", () => {
    const r = rule.analyze(ctxFromSource("true-positive-01-sampling-no-controls.ts"));
    const chain = r[0].chain;
    for (const link of chain.links) {
      if (link.type === "impact") continue;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(isLocation((link as any).location)).toBe(true);
    }
    for (const step of chain.verification_steps ?? []) {
      expect(isLocation(step.target)).toBe(true);
    }
    expect(chain.confidence).toBeLessThanOrEqual(0.75);
  });
});
