import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ToolPreferenceManipulationRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "__fixtures__");
const rule = new ToolPreferenceManipulationRule();

function ctx(name: string): AnalysisContext {
  const parsed = JSON.parse(readFileSync(join(FIX, name), "utf8")) as {
    tools: Array<{ name: string; description: string; input_schema: unknown }>;
  };
  return {
    server: { id: "j6", name: "j6", description: null, github_url: null },
    tools: parsed.tools as AnalysisContext["tools"],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}

describe("J6 — fires", () => {
  it("always use first", () => {
    const r = rule.analyze(ctx("true-positive-01-always-use-first.json"));
    expect(r.length).toBe(1);
    expect(r[0].severity).toBe("high");
  });
  it("replaces the old", () => {
    const r = rule.analyze(ctx("true-positive-02-replaces-old.json"));
    expect(r.length).toBe(1);
  });
  it("do not use other", () => {
    const r = rule.analyze(ctx("true-positive-03-deny-other.json"));
    expect(r.length).toBe(1);
  });
});

describe("J6 — does not fire", () => {
  it("plain description", () => {
    const r = rule.analyze(ctx("true-negative-01-plain.json"));
    expect(r.length).toBe(0);
  });
  it("docs tutorial", () => {
    const r = rule.analyze(ctx("true-negative-02-docs.json"));
    if (r.length > 0) {
      const factors = r[0].chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("false_positive_fence_triggered");
    } else {
      expect(r.length).toBe(0);
    }
  });
});

describe("J6 — evidence integrity", () => {
  it("structured Locations; cap 0.78", () => {
    const r = rule.analyze(ctx("true-positive-01-always-use-first.json"));
    for (const res of r) {
      for (const link of res.chain.links) {
        if (link.type === "impact") continue;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        expect(isLocation((link as any).location)).toBe(true);
      }
      for (const step of res.chain.verification_steps ?? []) {
        expect(isLocation(step.target)).toBe(true);
      }
      expect(res.chain.confidence).toBeLessThanOrEqual(0.78);
    }
  });
});
