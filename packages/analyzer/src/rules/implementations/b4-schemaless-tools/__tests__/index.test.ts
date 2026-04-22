import { describe, it, expect } from "vitest";
import "../index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { isLocation } from "../../../location.js";

import { buildContext as tp01 } from "../__fixtures__/true-positive-01-null-schema.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-undefined-schema.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-multiple-tools.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-has-schema.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-empty-object.js";

function rule() {
  const r = getTypedRuleV2("B4");
  if (!r) throw new Error("B4 rule not registered");
  return r;
}

describe("B4 True Positives", () => {
  it("TP-01 null schema fires", () => expect(rule().analyze(tp01()).length).toBe(1));
  it("TP-02 undefined schema fires", () => expect(rule().analyze(tp02()).length).toBe(1));
  it("TP-03 two null-schema tools → two findings", () =>
    expect(rule().analyze(tp03()).length).toBe(2));
});

describe("B4 True Negatives", () => {
  it("TN-01 schema with properties does not fire", () =>
    expect(rule().analyze(tn01()).length).toBe(0));
  it("TN-02 empty-object schema does not fire (out-of-scope for B4)", () =>
    expect(rule().analyze(tn02()).length).toBe(0));
});

describe("B4 Evidence Chain", () => {
  it("severity medium, structured locations", () => {
    const r = rule().analyze(tp01())[0];
    expect(r.severity).toBe("medium");
    for (const l of r.chain.links) {
      if (l.type === "impact") continue;
      expect(isLocation(l.location)).toBe(true);
    }
  });
});
