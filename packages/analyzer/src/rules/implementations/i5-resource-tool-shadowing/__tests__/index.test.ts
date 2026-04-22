import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ResourceToolShadowingRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "__fixtures__");

const rule = new ResourceToolShadowingRule();

function loadFixture(name: string): AnalysisContext {
  const parsed = JSON.parse(readFileSync(join(FIX, name), "utf8")) as {
    tools: Array<{ name: string; description: string; input_schema: unknown }>;
    resources: Array<{
      uri: string;
      name: string;
      description: string | null;
      mimeType: string | null;
    }>;
  };
  return {
    server: { id: "i5-t", name: "i5", description: null, github_url: null },
    tools: parsed.tools.map((t) => ({
      name: t.name,
      description: t.description,
      input_schema: t.input_schema,
    })) as AnalysisContext["tools"],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    resources: parsed.resources,
  };
}

describe("I5 — fires (true positives)", () => {
  it("flags exact collision with destructive tool (severity critical)", () => {
    const r = rule.analyze(loadFixture("true-positive-01-exact-destructive.json"));
    expect(r.length).toBe(1);
    expect(r[0].rule_id).toBe("I5");
    expect(r[0].severity).toBe("critical");
    expect(
      r[0].chain.confidence_factors.map((f) => f.factor),
    ).toContain("destructive_tool_vocabulary");
  });
  it("flags case-variant collision (case-normalised match)", () => {
    const r = rule.analyze(loadFixture("true-positive-02-case-variant.json"));
    expect(r.length).toBeGreaterThanOrEqual(1);
  });
  it("flags exact collision (non-destructive → high)", () => {
    const r = rule.analyze(loadFixture("true-positive-03-separator-variant.json"));
    expect(r.length).toBeGreaterThanOrEqual(1);
  });
});

describe("I5 — does not fire", () => {
  it("does NOT flag distinct names", () => {
    const r = rule.analyze(loadFixture("true-negative-01-distinct-names.json"));
    expect(r.length).toBe(0);
  });
  it("does NOT fire when no tools", () => {
    const r = rule.analyze(loadFixture("true-negative-02-resources-only.json"));
    expect(r.length).toBe(0);
  });
});

describe("I5 — evidence integrity", () => {
  it("locations on every link are structured Locations", () => {
    const r = rule.analyze(loadFixture("true-positive-01-exact-destructive.json"));
    const chain = r[0].chain;
    for (const link of chain.links) {
      if (link.type === "impact") continue;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(isLocation((link as any).location)).toBe(true);
    }
    for (const step of chain.verification_steps ?? []) {
      expect(isLocation(step.target)).toBe(true);
    }
  });

  it("confidence cap 0.80", () => {
    const r = rule.analyze(loadFixture("true-positive-01-exact-destructive.json"));
    expect(r[0].chain.confidence).toBeLessThanOrEqual(0.8);
  });
});
