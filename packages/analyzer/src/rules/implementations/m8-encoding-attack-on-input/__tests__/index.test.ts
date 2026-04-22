import { describe, it, expect } from "vitest";
import { M8Rule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";
import { source as tp01 } from "../__fixtures__/true-positive-01-atob-user.js";
import { source as tp02 } from "../__fixtures__/true-positive-02-decode-uri.js";
import { source as tp03 } from "../__fixtures__/true-positive-03-buffer-base64.js";
import { source as tn01 } from "../__fixtures__/true-negative-01-validator.js";
import { source as tn02 } from "../__fixtures__/true-negative-02-buffer-utf8.js";

function ctx(src: string, file = "scan.ts"): AnalysisContext {
  return {
    server: { id: "s", name: "n", description: null, github_url: null },
    tools: [],
    source_code: src,
    source_files: new Map([[file, src]]),
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new M8Rule();

describe("M8 — Encoding Attack on Tool Input (v2)", () => {
  it("fires on atob(req.body.payload) (TP-01)", () => {
    const fs = rule.analyze(ctx(tp01));
    expect(fs.length).toBeGreaterThanOrEqual(1);
  });
  it("fires on decodeURIComponent(req.query.name) (TP-02)", () => {
    const fs = rule.analyze(ctx(tp02));
    expect(fs.length).toBeGreaterThanOrEqual(1);
  });
  it("fires on Buffer.from(params.payload, 'base64') (TP-03)", () => {
    const fs = rule.analyze(ctx(tp03));
    expect(fs.length).toBeGreaterThanOrEqual(1);
  });
  it("does NOT fire when validate() is applied post-decode (TN-01)", () => {
    const fs = rule.analyze(ctx(tn01));
    expect(fs).toHaveLength(0);
  });
  it("does NOT fire for Buffer.from with utf-8 encoding (TN-02)", () => {
    const fs = rule.analyze(ctx(tn02));
    expect(fs).toHaveLength(0);
  });
  it("every non-impact link has structured Location", () => {
    const fs = rule.analyze(ctx(tp01));
    for (const link of fs[0].chain.links) {
      if (link.type === "impact") continue;
      expect(isLocation(link.location)).toBe(true);
    }
  });
  it("verification steps carry structured Locations", () => {
    const fs = rule.analyze(ctx(tp02));
    const steps = fs[0].chain.verification_steps ?? [];
    expect(steps.length).toBeGreaterThanOrEqual(3);
    for (const s of steps) expect(isLocation(s.target)).toBe(true);
  });
  it("respects the 0.80 confidence cap", () => {
    const fs = rule.analyze(ctx(tp01));
    for (const f of fs) expect(f.chain.confidence).toBeLessThanOrEqual(0.80);
  });
});
