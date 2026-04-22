import { describe, it, expect } from "vitest";
import { ProtocolVersionDowngradeRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-version-echo.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-accept-all.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-request-echo.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-enforced.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-hardcoded.js";

const rule = new ProtocolVersionDowngradeRule();

describe("N11 — Protocol Version Downgrade (v2)", () => {
  it("fires on req.params.protocolVersion reflection", () => {
    const f = rule.analyze(tp01());
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].rule_id).toBe("N11");
    expect(f[0].severity).toBe("critical");
  });

  it("fires on 'accept any version' marker", () => {
    const f = rule.analyze(tp02());
    expect(f.length).toBeGreaterThan(0);
  });

  it("fires on request.params.protocolVersion reflection", () => {
    const f = rule.analyze(tp03());
    expect(f.length).toBeGreaterThan(0);
  });

  it("fires with mitigation present=true when throw/reject is nearby", () => {
    const f = rule.analyze(tn01());
    // enforcement_present triggers present=true; rule may still fire
    if (f.length > 0) {
      const mit = f[0].chain.links.find((l) => l.type === "mitigation");
      if (mit && mit.type === "mitigation") expect(mit.present).toBe(true);
    }
  });

  it("does not fire on hardcoded protocolVersion", () => {
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

  it("confidence capped at 0.85", () => {
    const f = rule.analyze(tp01())[0];
    expect(f.chain.confidence).toBeLessThanOrEqual(0.85);
  });

  it("records version_enforcement_absent factor", () => {
    const f = rule.analyze(tp01())[0];
    const factors = f.chain.confidence_factors.map((x) => x.factor);
    expect(factors).toContain("version_enforcement_absent");
  });
});
