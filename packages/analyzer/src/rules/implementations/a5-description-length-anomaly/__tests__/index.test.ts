import { describe, it, expect } from "vitest";
import "../index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { isLocation } from "../../../location.js";

import { buildContext as tp01 } from "../__fixtures__/true-positive-01-padded.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-very-long.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-tail-injection.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-concise.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-just-under.js";

function rule() {
  const r = getTypedRuleV2("A5");
  if (!r) throw new Error("A5 rule not registered");
  return r;
}

describe("A5 True Positives", () => {
  it("TP-01 padded 1400-char description fires", () => {
    const r = rule().analyze(tp01());
    expect(r.length).toBe(1);
    expect(r[0].severity).toBe("low");
  });
  it("TP-02 very-long 5800-char description fires at higher confidence", () => {
    const r = rule().analyze(tp02());
    expect(r.length).toBe(1);
    expect(r[0].chain.confidence).toBeGreaterThan(0.4);
  });
  it("TP-03 tail-injection-length description fires", () => {
    expect(rule().analyze(tp03()).length).toBe(1);
  });
});

describe("A5 True Negatives", () => {
  it("TN-01 concise description does not fire", () => {
    expect(rule().analyze(tn01()).length).toBe(0);
  });
  it("TN-02 900-char description (just under threshold) does not fire", () => {
    expect(rule().analyze(tn02()).length).toBe(0);
  });
});

describe("A5 Evidence Chain", () => {
  it("confidence capped at 0.60", () => {
    expect(rule().analyze(tp02())[0].chain.confidence).toBeLessThanOrEqual(0.60);
  });
  it("locations are structured", () => {
    const r = rule().analyze(tp01())[0];
    for (const l of r.chain.links) {
      if (l.type === "impact") continue;
      expect(isLocation(l.location)).toBe(true);
    }
    for (const s of r.chain.verification_steps ?? []) {
      expect(isLocation(s.target)).toBe(true);
    }
  });
});
