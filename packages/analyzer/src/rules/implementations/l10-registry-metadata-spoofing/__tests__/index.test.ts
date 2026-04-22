import { describe, it, expect } from "vitest";
import { L10Rule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

import { source as tp01 } from "../__fixtures__/true-positive-01-author-anthropic.js";
import { source as tp02 } from "../__fixtures__/true-positive-02-publisher-structured.js";
import { source as tp03 } from "../__fixtures__/true-positive-03-ast-prop.js";
import { source as tn01 } from "../__fixtures__/true-negative-01-scoped-legit.js";
import { source as tn02 } from "../__fixtures__/true-negative-02-unrelated-author.js";

function ctx(src: string, file = "package.json"): AnalysisContext {
  return {
    server: { id: "s", name: "n", description: null, github_url: null },
    tools: [],
    source_code: src,
    source_files: new Map([[file, src]]),
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new L10Rule();

describe("L10 — Registry Metadata Spoofing (v2)", () => {
  it("fires on author: Anthropic (TP-01)", () => {
    const fs = rule.analyze(ctx(tp01));
    expect(fs.length).toBeGreaterThanOrEqual(1);
    expect(fs[0].severity).toBe("high");
  });

  it("fires on structured publisher.name: OpenAI (TP-02)", () => {
    const fs = rule.analyze(ctx(tp02));
    expect(fs.length).toBeGreaterThanOrEqual(1);
  });

  it("fires on AST-level author assignment (TP-03)", () => {
    const fs = rule.analyze(ctx(tp03, "manifest.ts"));
    expect(fs.length).toBeGreaterThanOrEqual(1);
  });

  it("does NOT fire when scoped package attests vendor (TN-01)", () => {
    const fs = rule.analyze(ctx(tn01));
    expect(fs).toHaveLength(0);
  });

  it("does NOT fire on unrelated author (TN-02)", () => {
    const fs = rule.analyze(ctx(tn02));
    expect(fs).toHaveLength(0);
  });

  it("every non-impact link has a structured Location", () => {
    const fs = rule.analyze(ctx(tp01));
    for (const link of fs[0].chain.links) {
      if (link.type === "impact") continue;
      expect(isLocation(link.location)).toBe(true);
    }
  });

  it("verification steps carry structured Locations", () => {
    const fs = rule.analyze(ctx(tp01));
    const steps = fs[0].chain.verification_steps ?? [];
    expect(steps.length).toBeGreaterThanOrEqual(3);
    for (const s of steps) expect(isLocation(s.target)).toBe(true);
  });

  it("respects the 0.80 confidence cap", () => {
    const fs = rule.analyze(ctx(tp01));
    for (const f of fs) expect(f.chain.confidence).toBeLessThanOrEqual(0.80);
  });

  it("threat reference is CoSAI-MCP-T6", () => {
    const fs = rule.analyze(ctx(tp01));
    expect(fs[0].chain.threat_reference?.id).toBe("CoSAI-MCP-T6");
  });
});
