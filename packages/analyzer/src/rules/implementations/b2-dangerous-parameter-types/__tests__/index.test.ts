import { describe, it, expect } from "vitest";
import "../index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { isLocation } from "../../../location.js";

import { buildContext as tp01 } from "../__fixtures__/true-positive-01-command.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-sql.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-code-template.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-safe.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-semantic.js";

function rule() {
  const r = getTypedRuleV2("B2");
  if (!r) throw new Error("B2 rule not registered");
  return r;
}

describe("B2 True Positives", () => {
  it("TP-01 'command' fires", () => expect(rule().analyze(tp01()).length).toBe(1));
  it("TP-02 'sql' fires", () => expect(rule().analyze(tp02()).length).toBe(1));
  it("TP-03 'code'+'template' fires", () => expect(rule().analyze(tp03()).length).toBe(1));
});

describe("B2 True Negatives", () => {
  it("TN-01 'city' does not fire", () => expect(rule().analyze(tn01()).length).toBe(0));
  it("TN-02 'operation'/'customer_id' does not fire", () =>
    expect(rule().analyze(tn02()).length).toBe(0));
});

describe("B2 Evidence Chain", () => {
  it("locations are structured and confidence capped", () => {
    const r = rule().analyze(tp01())[0];
    expect(r.chain.confidence).toBeLessThanOrEqual(0.85);
    for (const l of r.chain.links) {
      if (l.type === "impact") continue;
      expect(isLocation(l.location)).toBe(true);
    }
  });
  it("severity is high", () => {
    expect(rule().analyze(tp01())[0].severity).toBe("high");
  });
});
