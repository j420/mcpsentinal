import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { FullSchemaPoisoningRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "__fixtures__");
const rule = new FullSchemaPoisoningRule();

function loadFixture(name: string): AnalysisContext {
  const parsed = JSON.parse(readFileSync(join(FIX, name), "utf8")) as {
    tools: Array<{ name: string; description: string; input_schema: unknown }>;
  };
  return {
    server: { id: "j3", name: "j3", description: null, github_url: null },
    tools: parsed.tools as AnalysisContext["tools"],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}

describe("J3 — fires", () => {
  it("enum injection", () => {
    const r = rule.analyze(loadFixture("true-positive-01-enum-injection.json"));
    expect(r.length).toBe(1);
    expect(r[0].severity).toBe("critical");
  });
  it("delimiter in title", () => {
    const r = rule.analyze(loadFixture("true-positive-02-title-delim.json"));
    expect(r.length).toBe(1);
  });
  it("directive in default", () => {
    const r = rule.analyze(loadFixture("true-positive-03-default-directive.json"));
    expect(r.length).toBe(1);
  });
});

describe("J3 — does not fire", () => {
  it("clean enum", () => {
    const r = rule.analyze(loadFixture("true-negative-01-clean-enum.json"));
    expect(r.length).toBe(0);
  });
  it("no schema", () => {
    const r = rule.analyze(loadFixture("true-negative-02-no-schema.json"));
    expect(r.length).toBe(0);
  });
});

describe("J3 — evidence integrity", () => {
  it("structured Locations; cap 0.88; CyberArk reference", () => {
    const r = rule.analyze(loadFixture("true-positive-01-enum-injection.json"));
    const chain = r[0].chain;
    for (const link of chain.links) {
      if (link.type === "impact") continue;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(isLocation((link as any).location)).toBe(true);
    }
    for (const step of chain.verification_steps ?? []) {
      expect(isLocation(step.target)).toBe(true);
    }
    expect(chain.confidence).toBeLessThanOrEqual(0.88);
    expect(chain.threat_reference?.id).toBe("CyberArk-FSP-2025");
  });
});
