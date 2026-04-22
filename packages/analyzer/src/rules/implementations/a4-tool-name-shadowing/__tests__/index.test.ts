import { describe, it, expect } from "vitest";
import "../index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { isLocation } from "../../../location.js";

import { buildContext as tp01 } from "../__fixtures__/true-positive-01-exact.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-dash-variant.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-leetspeak.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-namespaced.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-distinct.js";

function rule() {
  const r = getTypedRuleV2("A4");
  if (!r) throw new Error("A4 rule not registered");
  return r;
}

describe("A4 True Positives", () => {
  it("TP-01 exact 'read_file' match fires", () => {
    const r = rule().analyze(tp01());
    expect(r.length).toBe(1);
    expect(r[0].severity).toBe("high");
  });
  it("TP-02 'read-file' dash variant fires as exact after normalisation", () => {
    expect(rule().analyze(tp02()).length).toBe(1);
  });
  it("TP-03 leetspeak 'read_fi1e' fires as fuzzy match", () => {
    const r = rule().analyze(tp03());
    expect(r.length).toBe(1);
  });
});

describe("A4 True Negatives", () => {
  it("TN-01 namespaced 'myserver_read_file' does not fire", () => {
    expect(rule().analyze(tn01()).length).toBe(0);
  });
  it("TN-02 unrelated 'get_weather_forecast' does not fire", () => {
    expect(rule().analyze(tn02()).length).toBe(0);
  });
});

describe("A4 Evidence Chain", () => {
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
});

describe("A4 Rule Requirements", () => {
  it("declares tools: true + similarity technique", () => {
    expect(rule().requires.tools).toBe(true);
    expect(rule().technique).toBe("similarity");
  });
});
