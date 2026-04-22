import { describe, it, expect } from "vitest";
import { JSONRPCErrorInjectionRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-throw-user-input.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-stringify-req-in-data.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-reject-error-query.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-generic-error.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-user-input-no-error.js";

const rule = new JSONRPCErrorInjectionRule();

describe("N4 — JSON-RPC Error Object Injection (v2)", () => {
  it("fires when req.params.name is interpolated into throw new Error", () => {
    const f = rule.analyze(tp01());
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].rule_id).toBe("N4");
    expect(f[0].severity).toBe("critical");
  });

  it("fires when JSON.stringify(req.body) lands in error.data", () => {
    const f = rule.analyze(tp02());
    expect(f.length).toBeGreaterThan(0);
  });

  it("fires when reject(new Error) embeds req.query", () => {
    const f = rule.analyze(tp03());
    expect(f.length).toBeGreaterThan(0);
  });

  it("does not fire on generic errors", () => {
    expect(rule.analyze(tn01()).length).toBe(0);
  });

  it("does not fire when user input never reaches error surface", () => {
    expect(rule.analyze(tn02()).length).toBe(0);
  });

  it("chain integrity — every link has a Location", () => {
    const f = rule.analyze(tp01())[0];
    for (const l of f.chain.links) {
      if (l.type === "impact") continue;
      expect(isLocation(l.location)).toBe(true);
    }
  });

  it("verification steps — targets are Locations", () => {
    const f = rule.analyze(tp01())[0];
    const steps = f.chain.verification_steps ?? [];
    expect(steps.length).toBeGreaterThan(0);
    for (const s of steps) expect(isLocation(s.target)).toBe(true);
  });

  it("confidence capped at 0.82", () => {
    const f = rule.analyze(tp01())[0];
    expect(f.chain.confidence).toBeLessThanOrEqual(0.82);
  });

  it("records user_input_to_error_path factor", () => {
    const f = rule.analyze(tp01())[0];
    const factors = f.chain.confidence_factors.map((x) => x.factor);
    expect(factors).toContain("user_input_to_error_path");
  });
});
