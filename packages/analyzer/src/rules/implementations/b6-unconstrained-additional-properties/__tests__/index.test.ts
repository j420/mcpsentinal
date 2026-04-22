import { describe, it, expect } from "vitest";
import "../index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { isLocation } from "../../../location.js";

import { buildContext as tp01 } from "../__fixtures__/true-positive-01-explicit-true.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-unset.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-multiple-tools.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-false.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-no-schema.js";

function rule() {
  const r = getTypedRuleV2("B6");
  if (!r) throw new Error("B6 rule not registered");
  return r;
}

describe("B6 True Positives", () => {
  it("TP-01 explicit additionalProperties: true fires", () =>
    expect(rule().analyze(tp01()).length).toBe(1));
  it("TP-02 unset additionalProperties fires", () =>
    expect(rule().analyze(tp02()).length).toBe(1));
  it("TP-03 two tools without false → two findings", () =>
    expect(rule().analyze(tp03()).length).toBe(2));
});

describe("B6 True Negatives", () => {
  it("TN-01 explicit false does not fire", () =>
    expect(rule().analyze(tn01()).length).toBe(0));
  it("TN-02 null schema does not fire (B4's domain)", () =>
    expect(rule().analyze(tn02()).length).toBe(0));
});

describe("B6 Evidence Chain", () => {
  it("severity medium and locations structured", () => {
    const r = rule().analyze(tp01())[0];
    expect(r.severity).toBe("medium");
    for (const l of r.chain.links) {
      if (l.type === "impact") continue;
      expect(isLocation(l.location)).toBe(true);
    }
  });
});
