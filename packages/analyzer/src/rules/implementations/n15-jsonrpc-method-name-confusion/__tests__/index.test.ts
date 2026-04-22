import { describe, it, expect } from "vitest";
import { MethodNameConfusionRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-user-input-dispatch.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-near-canonical.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-unicode-homoglyph.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-canonical-only.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-switch-dispatch.js";

const rule = new MethodNameConfusionRule();

describe("N15 — JSON-RPC Method Name Confusion (v2)", () => {
  it("fires on user-input dispatch via handlers[...]", () => {
    const f = rule.analyze(tp01());
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].rule_id).toBe("N15");
    expect(f[0].severity).toBe("critical");
  });

  it("fires on handler name near-canonical (tools/call2)", () => {
    const f = rule.analyze(tp02());
    expect(f.length).toBeGreaterThan(0);
    // Chain should reference the canonical method
    const factor = f[0].chain.confidence_factors.find((x) =>
      x.factor.startsWith("levenshtein_distance"),
    );
    expect(factor).toBeDefined();
  });

  it("fires on Unicode homoglyph in method name", () => {
    const f = rule.analyze(tp03());
    expect(f.length).toBeGreaterThan(0);
  });

  it("does not fire on canonical-only registrations", () => {
    expect(rule.analyze(tn01()).length).toBe(0);
  });

  it("does not fire on switch-based literal dispatch", () => {
    expect(rule.analyze(tn02()).length).toBe(0);
  });

  it("every link has Location", () => {
    const f = rule.analyze(tp01())[0];
    for (const l of f.chain.links) {
      if (l.type === "impact") continue;
      expect(isLocation(l.location)).toBe(true);
    }
  });

  it("verification steps target Locations", () => {
    const f = rule.analyze(tp01())[0];
    const steps = f.chain.verification_steps ?? [];
    expect(steps.length).toBeGreaterThan(0);
    for (const s of steps) expect(isLocation(s.target)).toBe(true);
  });

  it("confidence capped at 0.88", () => {
    const f = rule.analyze(tp01())[0];
    expect(f.chain.confidence).toBeLessThanOrEqual(0.88);
  });

  it("records method_name_confusion_type factor", () => {
    const f = rule.analyze(tp01())[0];
    const factors = f.chain.confidence_factors.map((x) => x.factor);
    expect(factors).toContain("method_name_confusion_type");
  });
});
