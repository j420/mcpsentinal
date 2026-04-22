/** O4 v2 — timing-side-channel unit tests. */
import { describe, it, expect } from "vitest";
import { O4Rule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

import { source as tp01 } from "../__fixtures__/true-positive-01-password-match.js";
import { source as tp02 } from "../__fixtures__/true-positive-02-delay-on-role.js";
import { source as tp03 } from "../__fixtures__/true-positive-03-token-conditional.js";
import { source as tn01 } from "../__fixtures__/true-negative-01-timing-safe.js";
import { source as tn02 } from "../__fixtures__/true-negative-02-jitter.js";

function ctx(src: string): AnalysisContext {
  return {
    server: { id: "s", name: "n", description: null, github_url: null },
    tools: [],
    source_code: src,
    source_files: new Map([["scan.ts", src]]),
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new O4Rule();

describe("O4 — Timing-Based Data Inference (v2)", () => {
  it("fires on setTimeout inside password-match branch (TP-01)", () => {
    const fs = rule.analyze(ctx(tp01));
    expect(fs.length).toBeGreaterThanOrEqual(1);
    expect(fs[0].rule_id).toBe("O4");
    expect(fs[0].severity).toBe("high");
  });

  it("fires on sleep inside user.role branch (TP-02)", () => {
    const fs = rule.analyze(ctx(tp02));
    expect(fs.length).toBeGreaterThanOrEqual(1);
  });

  it("fires on sleep inside token validation (TP-03)", () => {
    const fs = rule.analyze(ctx(tp03));
    expect(fs.length).toBeGreaterThanOrEqual(1);
  });

  it("does NOT fire when timingSafeEqual is present (TN-01)", () => {
    const fs = rule.analyze(ctx(tn01));
    expect(fs).toHaveLength(0);
  });

  it("does NOT fire when Math.random jitter is added (TN-02)", () => {
    const fs = rule.analyze(ctx(tn02));
    expect(fs).toHaveLength(0);
  });

  it("every non-impact link has a structured source Location", () => {
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

  it("respects the 0.85 confidence cap", () => {
    const fs = rule.analyze(ctx(tp01));
    for (const f of fs) expect(f.chain.confidence).toBeLessThanOrEqual(0.85);
  });

  it("threat reference is MITRE AML.T0057", () => {
    const fs = rule.analyze(ctx(tp01));
    expect(fs[0].chain.threat_reference?.id).toBe("MITRE-AML-T0057");
  });

  it("impact is data-exfiltration with user-data scope", () => {
    const fs = rule.analyze(ctx(tp01));
    const impact = fs[0].chain.links.find((l) => l.type === "impact");
    expect(impact && impact.type === "impact" && impact.impact_type).toBe("data-exfiltration");
    expect(impact && impact.type === "impact" && impact.scope).toBe("user-data");
  });
});
