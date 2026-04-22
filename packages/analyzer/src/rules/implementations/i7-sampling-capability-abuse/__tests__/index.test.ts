import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { SamplingCapabilityAbuseRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "__fixtures__");
const rule = new SamplingCapabilityAbuseRule();

function loadFixture(name: string): AnalysisContext {
  const parsed = JSON.parse(readFileSync(join(FIX, name), "utf8")) as {
    declared_capabilities: Record<string, boolean>;
    tools: Array<{ name: string; description: string; input_schema: unknown }>;
  };
  return {
    server: { id: "i7", name: "i7", description: null, github_url: null },
    tools: parsed.tools as AnalysisContext["tools"],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    declared_capabilities: parsed.declared_capabilities,
  };
}

describe("I7 — fires", () => {
  it("sampling + web fetch tool", () => {
    const r = rule.analyze(loadFixture("true-positive-01-sampling-plus-web.json"));
    expect(r.length).toBe(1);
    expect(r[0].severity).toBe("critical");
  });
  it("sampling + email reader", () => {
    const r = rule.analyze(loadFixture("true-positive-02-sampling-plus-email.json"));
    expect(r.length).toBe(1);
  });
});

describe("I7 — does not fire", () => {
  it("no sampling capability", () => {
    const r = rule.analyze(loadFixture("true-negative-01-no-sampling.json"));
    expect(r.length).toBe(0);
  });
  it("sampling but no ingestion", () => {
    const r = rule.analyze(loadFixture("true-negative-02-sampling-without-ingestion.json"));
    expect(r.length).toBe(0);
  });
});

describe("I7 — evidence integrity", () => {
  it("structured Locations everywhere; confidence cap 0.88", () => {
    const r = rule.analyze(loadFixture("true-positive-01-sampling-plus-web.json"));
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
  });
});
