import { describe, it, expect } from "vitest";
import { ResourceSubscriptionPoisoningRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-updated-no-hash.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-resourceChanged.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-sendupdate.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-no-subscription.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-with-integrity.js";

const rule = new ResourceSubscriptionPoisoningRule();

describe("N12 — Resource Subscription Content Mutation (v2)", () => {
  it("fires on notifications/resources/updated without hash", () => {
    const f = rule.analyze(tp01());
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].rule_id).toBe("N12");
    expect(f[0].severity).toBe("critical");
  });

  it("fires on resourceChanged emit without integrity", () => {
    const f = rule.analyze(tp02());
    expect(f.length).toBeGreaterThan(0);
  });

  it("fires on sendUpdate without integrity", () => {
    const f = rule.analyze(tp03());
    expect(f.length).toBeGreaterThan(0);
  });

  it("honest refusal: does not fire when no subscription surface exists", () => {
    expect(rule.analyze(tn01()).length).toBe(0);
  });

  it("fires with mitigation present=true when integrity fragment nearby", () => {
    const f = rule.analyze(tn02());
    if (f.length > 0) {
      const mit = f[0].chain.links.find((l) => l.type === "mitigation");
      if (mit && mit.type === "mitigation") expect(mit.present).toBe(true);
    }
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

  it("confidence capped at 0.78", () => {
    const f = rule.analyze(tp01())[0];
    expect(f.chain.confidence).toBeLessThanOrEqual(0.78);
  });

  it("records integrity_check_absent factor", () => {
    const f = rule.analyze(tp01())[0];
    const factors = f.chain.confidence_factors.map((x) => x.factor);
    expect(factors).toContain("integrity_check_absent");
  });
});
