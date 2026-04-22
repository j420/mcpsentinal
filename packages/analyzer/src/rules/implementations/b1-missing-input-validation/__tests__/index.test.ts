import { describe, it, expect } from "vitest";
import "../index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { isLocation } from "../../../location.js";

import { buildContext as tp01 } from "../__fixtures__/true-positive-01-unconstrained-string.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-unconstrained-number.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-multiple.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-constrained-string.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-constrained-number.js";

function rule() {
  const r = getTypedRuleV2("B1");
  if (!r) throw new Error("B1 rule not registered");
  return r;
}

describe("B1 True Positives", () => {
  it("TP-01 unconstrained string fires", () => {
    expect(rule().analyze(tp01()).length).toBe(1);
  });
  it("TP-02 unconstrained number fires", () => {
    expect(rule().analyze(tp02()).length).toBe(1);
  });
  it("TP-03 multiple unconstrained params fire", () => {
    const r = rule().analyze(tp03());
    expect(r.length).toBe(1);
    expect(r[0].severity).toBe("medium");
  });
});

describe("B1 True Negatives", () => {
  it("TN-01 constrained string does not fire", () => {
    expect(rule().analyze(tn01()).length).toBe(0);
  });
  it("TN-02 constrained number does not fire", () => {
    expect(rule().analyze(tn02()).length).toBe(0);
  });
});

describe("B1 Evidence Chain", () => {
  it("confidence capped at 0.85", () => {
    expect(rule().analyze(tp03())[0].chain.confidence).toBeLessThanOrEqual(0.85);
  });
  it("locations are structured", () => {
    const r = rule().analyze(tp01())[0];
    for (const l of r.chain.links) {
      if (l.type === "impact") continue;
      expect(isLocation(l.location)).toBe(true);
    }
  });
});
