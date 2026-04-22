import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { PromptTemplateInjectionRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "__fixtures__");

const rule = new PromptTemplateInjectionRule();

function loadFixture(name: string): AnalysisContext {
  const parsed = JSON.parse(readFileSync(join(FIX, name), "utf8")) as {
    prompts: Array<{
      name: string;
      description: string | null;
      arguments: Array<{ name: string; description: string | null; required: boolean }>;
    }>;
  };
  return {
    server: { id: "i6-t", name: "i6", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    prompts: parsed.prompts,
  };
}

describe("I6 — fires (true positives)", () => {
  it("flags role-override in prompt description", () => {
    const r = rule.analyze(loadFixture("true-positive-01-role-override.json"));
    expect(r.length).toBe(1);
    expect(r[0].severity).toBe("critical");
  });
  it("flags payload in argument description", () => {
    const r = rule.analyze(loadFixture("true-positive-02-argument-payload.json"));
    expect(r.length).toBe(1);
  });
  it("flags LLM delimiter in prompt name", () => {
    const r = rule.analyze(loadFixture("true-positive-03-delimiter.json"));
    expect(r.length).toBe(1);
  });
});

describe("I6 — does not fire", () => {
  it("benign code-review template", () => {
    const r = rule.analyze(loadFixture("true-negative-01-benign-template.json"));
    expect(r.length).toBe(0);
  });
  it("release-notes template", () => {
    const r = rule.analyze(loadFixture("true-negative-02-readme-example.json"));
    expect(r.length).toBe(0);
  });
});

describe("I6 — evidence integrity", () => {
  it("all locations are structured Locations", () => {
    const r = rule.analyze(loadFixture("true-positive-01-role-override.json"));
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

  it("confidence cap 0.85", () => {
    const r = rule.analyze(loadFixture("true-positive-01-role-override.json"));
    expect(r[0].chain.confidence).toBeLessThanOrEqual(0.85);
  });
});
