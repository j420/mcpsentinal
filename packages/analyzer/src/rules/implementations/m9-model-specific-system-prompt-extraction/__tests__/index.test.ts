import { describe, it, expect } from "vitest";
import { SystemPromptExtractionRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-return-system-prompt.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-res-send-initial-prompt.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-respond-system-instructions.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-no-prompt-leak.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-setter-only.js";

const rule = new SystemPromptExtractionRule();

describe("M9 — System Prompt Extraction (v2)", () => {
  it("lethal-edge #1 — return system_prompt verbatim", () => {
    const f = rule.analyze(tp01());
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].rule_id).toBe("M9");
    expect(f[0].severity).toBe("critical");
  });

  it("lethal-edge #2 — res.json with initial_prompt", () => {
    const f = rule.analyze(tp02());
    expect(f.length).toBeGreaterThan(0);
  });

  it("lethal-edge #3 — respond() with system_instructions", () => {
    const f = rule.analyze(tp03());
    expect(f.length).toBeGreaterThan(0);
  });

  it("does not fire on safe code", () => {
    expect(rule.analyze(tn01()).length).toBe(0);
  });

  it("does not fire on setter-only code", () => {
    expect(rule.analyze(tn02()).length).toBe(0);
  });

  it("every link has structured Location", () => {
    const f = rule.analyze(tp01())[0];
    for (const l of f.chain.links) {
      if (l.type === "impact") continue;
      expect(isLocation(l.location)).toBe(true);
    }
  });

  it("every verification step target is a Location", () => {
    const f = rule.analyze(tp01())[0];
    const steps = f.chain.verification_steps ?? [];
    expect(steps.length).toBeGreaterThan(0);
    for (const s of steps) expect(isLocation(s.target)).toBe(true);
  });

  it("confidence capped at 0.80", () => {
    const f = rule.analyze(tp01())[0];
    expect(f.chain.confidence).toBeLessThanOrEqual(0.8);
  });

  it("records prompt_identifier_specificity factor", () => {
    const f = rule.analyze(tp01())[0];
    const factors = f.chain.confidence_factors.map((x) => x.factor);
    expect(factors).toContain("prompt_identifier_specificity");
  });
});
