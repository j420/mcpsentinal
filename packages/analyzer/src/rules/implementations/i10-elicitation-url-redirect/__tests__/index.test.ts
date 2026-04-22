import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ElicitationUrlRedirectRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "__fixtures__");
const rule = new ElicitationUrlRedirectRule();

function loadFixture(name: string): AnalysisContext {
  const parsed = JSON.parse(readFileSync(join(FIX, name), "utf8")) as {
    tools: Array<{ name: string; description: string; input_schema: unknown }>;
  };
  return {
    server: { id: "i10", name: "i10", description: null, github_url: null },
    tools: parsed.tools as AnalysisContext["tools"],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}

describe("I10 — fires", () => {
  it("redirect to login URL", () => {
    const r = rule.analyze(loadFixture("true-positive-01-auth-redirect.json"));
    expect(r.length).toBe(1);
    expect(r[0].severity).toBe("high");
  });
  it("navigate to verification link", () => {
    const r = rule.analyze(loadFixture("true-positive-02-navigate-link.json"));
    expect(r.length).toBe(1);
  });
});

describe("I10 — does not fire", () => {
  it("benign report tool", () => {
    const r = rule.analyze(loadFixture("true-negative-01-benign-tool.json"));
    expect(r.length).toBe(0);
  });
  it("docs example about redirect — fence demotes or no fire", () => {
    const r = rule.analyze(loadFixture("true-negative-02-docs-redirect.json"));
    if (r.length > 0) {
      const factors = r[0].chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("false_positive_fence_triggered");
    } else {
      expect(r.length).toBe(0);
    }
  });
});

describe("I10 — evidence integrity", () => {
  it("structured Locations; cap 0.80", () => {
    const r = rule.analyze(loadFixture("true-positive-01-auth-redirect.json"));
    const chain = r[0].chain;
    for (const link of chain.links) {
      if (link.type === "impact") continue;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(isLocation((link as any).location)).toBe(true);
    }
    for (const step of chain.verification_steps ?? []) {
      expect(isLocation(step.target)).toBe(true);
    }
    expect(chain.confidence).toBeLessThanOrEqual(0.8);
  });
});
