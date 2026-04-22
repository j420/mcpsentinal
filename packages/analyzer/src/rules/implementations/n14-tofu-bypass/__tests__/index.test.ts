import { describe, it, expect } from "vitest";
import { TOFUBypassRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-ignore-fingerprint.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-accept-first.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-reject-unauthorized.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-no-tofu-context.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-correct-pinning.js";

const rule = new TOFUBypassRule();

describe("N14 — TOFU Bypass (v2)", () => {
  it("fires on ignoreFingerprint flag", () => {
    const f = rule.analyze(tp01());
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].rule_id).toBe("N14");
    expect(f[0].severity).toBe("critical");
  });

  it("fires on accept-first-identity pattern", () => {
    const f = rule.analyze(tp02());
    expect(f.length).toBeGreaterThan(0);
  });

  it("fires on rejectUnauthorized: false", () => {
    const f = rule.analyze(tp03());
    expect(f.length).toBeGreaterThan(0);
  });

  it("honest refusal: no TOFU context → no finding", () => {
    expect(rule.analyze(tn01()).length).toBe(0);
  });

  it("does not fire on correct pinning code", () => {
    expect(rule.analyze(tn02()).length).toBe(0);
  });

  it("every link has Location", () => {
    const f = rule.analyze(tp01())[0];
    for (const l of f.chain.links) {
      if (l.type === "impact") continue;
      expect(isLocation(l.location)).toBe(true);
    }
  });

  it("verification targets are Locations", () => {
    const f = rule.analyze(tp01())[0];
    const steps = f.chain.verification_steps ?? [];
    expect(steps.length).toBeGreaterThan(0);
    for (const s of steps) expect(isLocation(s.target)).toBe(true);
  });

  it("confidence capped at 0.78", () => {
    const f = rule.analyze(tp01())[0];
    expect(f.chain.confidence).toBeLessThanOrEqual(0.78);
  });

  it("records pinning_bypass_detected factor", () => {
    const f = rule.analyze(tp01())[0];
    const factors = f.chain.confidence_factors.map((x) => x.factor);
    expect(factors).toContain("pinning_bypass_detected");
  });
});
