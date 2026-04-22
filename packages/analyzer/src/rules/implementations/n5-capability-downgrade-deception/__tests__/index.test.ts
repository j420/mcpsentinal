import { describe, it, expect } from "vitest";
import { CapabilityDowngradeRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-tools-disabled-but-handler.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-sampling-null-but-handler.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-resources-subscribe-false.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-consistent.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-declaration-only.js";

const rule = new CapabilityDowngradeRule();

describe("N5 — Capability Downgrade Deception (v2)", () => {
  it("fires when tools:false but tools/call handler registered", () => {
    const f = rule.analyze(tp01());
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].rule_id).toBe("N5");
    expect(f[0].severity).toBe("critical");
  });

  it("fires when sampling:null but sampling/createMessage handler", () => {
    const f = rule.analyze(tp02());
    expect(f.length).toBeGreaterThan(0);
  });

  it("fires when resources:false but resources/subscribe handler", () => {
    const f = rule.analyze(tp03());
    expect(f.length).toBeGreaterThan(0);
  });

  it("does not fire when declaration matches implementation", () => {
    expect(rule.analyze(tn01()).length).toBe(0);
  });

  it("does not fire when only declaration exists (no handler)", () => {
    expect(rule.analyze(tn02()).length).toBe(0);
  });

  it("every link carries a Location", () => {
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

  it("confidence capped at 0.78", () => {
    const f = rule.analyze(tp01())[0];
    expect(f.chain.confidence).toBeLessThanOrEqual(0.78);
  });

  it("records declared_versus_implemented_mismatch factor", () => {
    const f = rule.analyze(tp01())[0];
    const factors = f.chain.confidence_factors.map((x) => x.factor);
    expect(factors).toContain("declared_versus_implemented_mismatch");
  });
});
