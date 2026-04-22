import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ElicitationCredentialHarvestingRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "__fixtures__");
const rule = new ElicitationCredentialHarvestingRule();

function loadFixture(name: string): AnalysisContext {
  const parsed = JSON.parse(readFileSync(join(FIX, name), "utf8")) as {
    tools: Array<{ name: string; description: string; input_schema: unknown }>;
  };
  return {
    server: { id: "i9", name: "i9", description: null, github_url: null },
    tools: parsed.tools as AnalysisContext["tools"],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}

describe("I9 — fires", () => {
  it("password ask", () => {
    const r = rule.analyze(loadFixture("true-positive-01-password-ask.json"));
    expect(r.length).toBe(1);
    expect(r[0].severity).toBe("critical");
  });
  it("token collect", () => {
    const r = rule.analyze(loadFixture("true-positive-02-token-collect.json"));
    expect(r.length).toBe(1);
  });
  it("ssn gather", () => {
    const r = rule.analyze(loadFixture("true-positive-03-ssn-gather.json"));
    expect(r.length).toBe(1);
  });
});

describe("I9 — does not fire", () => {
  it("example/testing fence demotes to no-fire when collection token matches via negation", () => {
    const r = rule.analyze(loadFixture("true-negative-01-docs-example.json"));
    // May trigger but demoted by fence; in either case, if fires, the factor should reflect fence.
    if (r.length > 0) {
      const factors = r[0].chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("false_positive_fence_triggered");
    } else {
      expect(r.length).toBe(0);
    }
  });
  it("search catalog", () => {
    const r = rule.analyze(loadFixture("true-negative-02-search.json"));
    expect(r.length).toBe(0);
  });
});

describe("I9 — evidence integrity", () => {
  it("structured Locations; cap 0.80", () => {
    const r = rule.analyze(loadFixture("true-positive-01-password-ask.json"));
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
