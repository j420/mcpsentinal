import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { OpenApiSpecFieldInjectionRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "__fixtures__");
const rule = new OpenApiSpecFieldInjectionRule();

function ctx(name: string): AnalysisContext {
  return {
    server: { id: "j7", name: "j7", description: null, github_url: null },
    tools: [],
    source_code: readFileSync(join(FIX, name), "utf8"),
    dependencies: [],
    connection_metadata: null,
  };
}

describe("J7 — fires", () => {
  it("summary in template literal", () => {
    const r = rule.analyze(ctx("true-positive-01-summary-template.ts"));
    expect(r.length).toBeGreaterThanOrEqual(1);
    expect(r[0].severity).toBe("critical");
    const refId = r[0].chain.threat_reference?.id;
    expect(refId === "CVE-2026-22785" || refId === "CVE-2026-23947").toBe(true);
  });
  it("operationId concat", () => {
    const r = rule.analyze(ctx("true-positive-02-operationid-concat.ts"));
    expect(r.length).toBeGreaterThanOrEqual(1);
  });
});

describe("J7 — does not fire", () => {
  it("AST-built generator", () => {
    const r = rule.analyze(ctx("true-negative-01-ast-build.ts"));
    expect(r.length).toBe(0);
  });
  it("unrelated template literal", () => {
    const r = rule.analyze(ctx("true-negative-02-no-openapi.ts"));
    expect(r.length).toBe(0);
  });
});

describe("J7 — evidence integrity", () => {
  it("structured Locations; cap 0.88; CVE-2026-22785 / 23947 reference", () => {
    const r = rule.analyze(ctx("true-positive-01-summary-template.ts"));
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
