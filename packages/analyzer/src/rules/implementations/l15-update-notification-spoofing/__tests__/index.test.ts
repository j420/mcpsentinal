import { describe, it, expect } from "vitest";
import { L15Rule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

import { source as tp01 } from "../__fixtures__/true-positive-01-notification-with-install.js";
import { source as tp02 } from "../__fixtures__/true-positive-02-pipe-to-shell.js";
import { source as tp03 } from "../__fixtures__/true-positive-03-please-upgrade.js";
import { source as tn01 } from "../__fixtures__/true-negative-01-legitimate-library.js";
import { source as tn02 } from "../__fixtures__/true-negative-02-plain-string.js";

function ctx(src: string, file = "notify.ts"): AnalysisContext {
  return {
    server: { id: "s", name: "n", description: null, github_url: null },
    tools: [],
    source_code: src,
    source_files: new Map([[file, src]]),
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new L15Rule();

describe("L15 — Update Notification Spoofing (v2)", () => {
  it("fires on notification + npm install (TP-01)", () => {
    const fs = rule.analyze(ctx(tp01));
    expect(fs.length).toBeGreaterThanOrEqual(1);
    expect(fs[0].severity).toBe("high");
  });

  it("fires on notification + curl|bash pipe (TP-02)", () => {
    const fs = rule.analyze(ctx(tp02));
    expect(fs.length).toBeGreaterThanOrEqual(1);
  });

  it("fires on 'please upgrade' + pnpm add (TP-03)", () => {
    const fs = rule.analyze(ctx(tp03));
    expect(fs.length).toBeGreaterThanOrEqual(1);
  });

  it("does NOT fire when update-notifier library is in scope (TN-01)", () => {
    const fs = rule.analyze(ctx(tn01));
    expect(fs).toHaveLength(0);
  });

  it("does NOT fire on plain string (TN-02)", () => {
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
    const fs = rule.analyze(ctx(tp02));
    const steps = fs[0].chain.verification_steps ?? [];
    expect(steps.length).toBeGreaterThanOrEqual(3);
    for (const s of steps) expect(isLocation(s.target)).toBe(true);
  });

  it("respects the 0.80 confidence cap", () => {
    const fs = rule.analyze(ctx(tp01));
    for (const f of fs) expect(f.chain.confidence).toBeLessThanOrEqual(0.80);
  });

  it("threat reference is OWASP-ASI04", () => {
    const fs = rule.analyze(ctx(tp01));
    expect(fs[0].chain.threat_reference?.id).toBe("OWASP-ASI04");
  });
});
