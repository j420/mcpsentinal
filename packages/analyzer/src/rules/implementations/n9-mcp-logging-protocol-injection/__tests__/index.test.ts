import { describe, it, expect } from "vitest";
import { LoggingProtocolInjectionRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-sendlogmessage-user.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-notifications-message.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-logger-user-input.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-no-user-input.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-user-input-no-log.js";

const rule = new LoggingProtocolInjectionRule();

describe("N9 — MCP Logging Protocol Injection (v2)", () => {
  it("fires when sendLogMessage receives user input", () => {
    const f = rule.analyze(tp01());
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].rule_id).toBe("N9");
    expect(f[0].severity).toBe("critical");
  });

  it("fires when notifications/message emits user body", () => {
    const f = rule.analyze(tp02());
    expect(f.length).toBeGreaterThan(0);
  });

  it("fires when logger.info templates in user input", () => {
    const f = rule.analyze(tp03());
    expect(f.length).toBeGreaterThan(0);
  });

  it("does not fire on constant-string logging", () => {
    expect(rule.analyze(tn01()).length).toBe(0);
  });

  it("does not fire when user input never reaches a log surface", () => {
    expect(rule.analyze(tn02()).length).toBe(0);
  });

  it("every link has Location", () => {
    const f = rule.analyze(tp01())[0];
    for (const l of f.chain.links) {
      if (l.type === "impact") continue;
      expect(isLocation(l.location)).toBe(true);
    }
  });

  it("verification targets are Location", () => {
    const f = rule.analyze(tp01())[0];
    const steps = f.chain.verification_steps ?? [];
    expect(steps.length).toBeGreaterThan(0);
    for (const s of steps) expect(isLocation(s.target)).toBe(true);
  });

  it("confidence capped at 0.82", () => {
    const f = rule.analyze(tp01())[0];
    expect(f.chain.confidence).toBeLessThanOrEqual(0.82);
  });

  it("records user_input_to_log_path factor", () => {
    const f = rule.analyze(tp01())[0];
    const factors = f.chain.confidence_factors.map((x) => x.factor);
    expect(factors).toContain("user_input_to_log_path");
  });
});
