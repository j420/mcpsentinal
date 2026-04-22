import { describe, it, expect } from "vitest";
import "../index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { isLocation } from "../../../location.js";

import { buildContext as tp01 } from "../__fixtures__/true-positive-01-readonly-with-delete.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-safe-with-webhook.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-nondestructive-with-overwrite.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-honest.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-readonly-for-real.js";

function rule() {
  const r = getTypedRuleV2("A8");
  if (!r) throw new Error("A8 rule not registered");
  return r;
}

describe("A8 True Positives", () => {
  it("TP-01 read-only claim + delete parameter fires", () => {
    const r = rule().analyze(tp01());
    expect(r.length).toBe(1);
    expect(r[0].severity).toBe("high");
  });
  it("TP-02 safe claim + webhook_url parameter fires", () => {
    expect(rule().analyze(tp02()).length).toBe(1);
  });
  it("TP-03 non-destructive claim + overwrite=true default fires", () => {
    expect(rule().analyze(tp03()).length).toBe(1);
  });
});

describe("A8 True Negatives", () => {
  it("TN-01 honest destructive tool does not fire", () => {
    expect(rule().analyze(tn01()).length).toBe(0);
  });
  it("TN-02 genuinely read-only tool does not fire", () => {
    expect(rule().analyze(tn02()).length).toBe(0);
  });
});

describe("A8 Evidence Chain", () => {
  it("confidence capped at 0.80", () => {
    expect(rule().analyze(tp01())[0].chain.confidence).toBeLessThanOrEqual(0.80);
  });
  it("locations are structured", () => {
    const r = rule().analyze(tp01())[0];
    for (const l of r.chain.links) {
      if (l.type === "impact") continue;
      expect(isLocation(l.location)).toBe(true);
    }
  });
  it("chain has source + propagation + sink + impact", () => {
    const types = rule().analyze(tp01())[0].chain.links.map((l) => l.type);
    expect(types).toContain("source");
    expect(types).toContain("propagation");
    expect(types).toContain("sink");
    expect(types).toContain("impact");
  });
});
