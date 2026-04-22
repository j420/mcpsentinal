import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { CapabilityEscalationPostInitRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "__fixtures__");
const rule = new CapabilityEscalationPostInitRule();

function ctx(srcFile: string, declared: Record<string, boolean>): AnalysisContext {
  return {
    server: { id: "i12", name: "i12", description: null, github_url: null },
    tools: [],
    source_code: readFileSync(join(FIX, srcFile), "utf8"),
    dependencies: [],
    connection_metadata: null,
    declared_capabilities: declared,
  };
}

describe("I12 — fires", () => {
  it("sampling handlers but sampling not declared", () => {
    const r = rule.analyze(ctx("true-positive-01-sampling-undeclared.ts", { tools: true }));
    const samplingFindings = r.filter((x) =>
      x.chain.links.some(
        (l) =>
          (l.type === "source" || l.type === "sink") &&
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          ((l as any).location?.capability === "sampling"),
      ),
    );
    expect(samplingFindings.length).toBe(1);
    expect(samplingFindings[0].severity).toBe("critical");
  });
  it("tool handlers but tools not declared", () => {
    const r = rule.analyze(ctx("true-positive-02-tools-undeclared.ts", { resources: true }));
    expect(r.length).toBeGreaterThanOrEqual(1);
  });
});

describe("I12 — does not fire", () => {
  it("tool handlers + tools declared", () => {
    const r = rule.analyze(ctx("true-negative-01-matches-declared.ts", { tools: true }));
    expect(r.length).toBe(0);
  });
  it("no handlers at all", () => {
    const r = rule.analyze(ctx("true-negative-02-no-capabilities.ts", { tools: false }));
    expect(r.length).toBe(0);
  });
});

describe("I12 — evidence integrity", () => {
  it("structured Locations; cap 0.88", () => {
    const r = rule.analyze(ctx("true-positive-01-sampling-undeclared.ts", { tools: true }));
    for (const res of r) {
      for (const link of res.chain.links) {
        if (link.type === "impact") continue;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        expect(isLocation((link as any).location)).toBe(true);
      }
      for (const step of res.chain.verification_steps ?? []) {
        expect(isLocation(step.target)).toBe(true);
      }
      expect(res.chain.confidence).toBeLessThanOrEqual(0.88);
    }
  });
});
