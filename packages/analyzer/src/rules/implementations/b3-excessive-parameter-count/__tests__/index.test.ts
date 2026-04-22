import { describe, it, expect } from "vitest";
import "../index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { isLocation } from "../../../location.js";

import { buildContext as tp01 } from "../__fixtures__/true-positive-01-twenty-params.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-fifty-params.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-sixteen-params.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-few-params.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-at-threshold.js";

function rule() {
  const r = getTypedRuleV2("B3");
  if (!r) throw new Error("B3 rule not registered");
  return r;
}

describe("B3 True Positives", () => {
  it("TP-01 20 params fires", () => expect(rule().analyze(tp01()).length).toBe(1));
  it("TP-02 50 params fires", () => expect(rule().analyze(tp02()).length).toBe(1));
  it("TP-03 16 params (just over threshold) fires", () =>
    expect(rule().analyze(tp03()).length).toBe(1));
});

describe("B3 True Negatives", () => {
  it("TN-01 2 params does not fire", () => expect(rule().analyze(tn01()).length).toBe(0));
  it("TN-02 15 params (at threshold) does not fire", () =>
    expect(rule().analyze(tn02()).length).toBe(0));
});

describe("B3 Evidence Chain", () => {
  it("severity is low and location is structured", () => {
    const r = rule().analyze(tp01())[0];
    expect(r.severity).toBe("low");
    for (const l of r.chain.links) {
      if (l.type === "impact") continue;
      expect(isLocation(l.location)).toBe(true);
    }
  });
});
