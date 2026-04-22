import { describe, it, expect } from "vitest";
import "../index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { isLocation } from "../../../location.js";

import { buildContext as tp01 } from "../__fixtures__/true-positive-01-shortener.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-webhook-canary.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-tunnel.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-github.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-no-url.js";

function rule() {
  const r = getTypedRuleV2("A3");
  if (!r) throw new Error("A3 rule not registered");
  return r;
}

describe("A3 True Positives", () => {
  it("TP-01 bit.ly shortener fires", () => {
    const r = rule().analyze(tp01());
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].severity).toBe("medium");
  });
  it("TP-02 webhook.site canary fires high", () => {
    const r = rule().analyze(tp02());
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].severity).toBe("high");
  });
  it("TP-03 ngrok tunnel fires", () => {
    const r = rule().analyze(tp03());
    expect(r.length).toBeGreaterThan(0);
  });
});

describe("A3 True Negatives", () => {
  it("TN-01 github.com URL does not fire", () => {
    expect(rule().analyze(tn01()).length).toBe(0);
  });
  it("TN-02 description with no URL does not fire", () => {
    expect(rule().analyze(tn02()).length).toBe(0);
  });
});

describe("A3 Evidence Chain", () => {
  it("locations are structured", () => {
    const r = rule().analyze(tp02())[0];
    for (const l of r.chain.links) {
      if (l.type === "impact") continue;
      expect(isLocation(l.location)).toBe(true);
    }
    for (const s of r.chain.verification_steps ?? []) {
      expect(isLocation(s.target)).toBe(true);
    }
  });
  it("confidence capped at 0.90", () => {
    expect(rule().analyze(tp02())[0].chain.confidence).toBeLessThanOrEqual(0.90);
  });
  it("chain includes source + propagation + sink + impact", () => {
    const types = rule().analyze(tp02())[0].chain.links.map((l) => l.type);
    expect(types).toContain("source");
    expect(types).toContain("propagation");
    expect(types).toContain("sink");
    expect(types).toContain("impact");
  });
});
