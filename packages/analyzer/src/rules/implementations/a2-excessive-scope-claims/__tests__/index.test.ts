import { describe, it, expect } from "vitest";
import "../index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { isLocation, type Location } from "../../../location.js";

import { buildContext as tp01 } from "../__fixtures__/true-positive-01-unrestricted-access.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-admin-mode.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-delete-all.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-scoped.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-specific.js";

function rule() {
  const r = getTypedRuleV2("A2");
  if (!r) throw new Error("A2 rule not registered");
  return r;
}

describe("A2 True Positives", () => {
  it("TP-01 'full access' + 'all file' fires", () => {
    const r = rule().analyze(tp01());
    expect(r.length).toBe(1);
    expect(r[0].severity).toBe("high");
  });
  it("TP-02 'admin mode' + 'any records' fires", () => {
    const r = rule().analyze(tp02());
    expect(r.length).toBe(1);
  });
  it("TP-03 'delete any' + 'complete control' fires", () => {
    const r = rule().analyze(tp03());
    expect(r.length).toBe(1);
  });
});

describe("A2 True Negatives", () => {
  it("TN-01 scoped weather description does not fire", () => {
    expect(rule().analyze(tn01()).length).toBe(0);
  });
  it("TN-02 specific calculator does not fire", () => {
    expect(rule().analyze(tn02()).length).toBe(0);
  });
});

describe("A2 Evidence Chain", () => {
  it("links and verification targets are Locations", () => {
    const r = rule().analyze(tp01())[0];
    for (const l of r.chain.links) {
      if (l.type === "impact") continue;
      expect(isLocation(l.location)).toBe(true);
      if (isLocation(l.location)) expect((l.location as Location).kind).toBe("tool");
    }
    for (const s of r.chain.verification_steps ?? []) {
      expect(isLocation(s.target)).toBe(true);
    }
  });
  it("confidence capped at 0.80", () => {
    expect(rule().analyze(tp01())[0].chain.confidence).toBeLessThanOrEqual(0.80);
  });
  it("chain has source + propagation + sink + impact", () => {
    const types = rule().analyze(tp01())[0].chain.links.map((l) => l.type);
    expect(types).toContain("source");
    expect(types).toContain("propagation");
    expect(types).toContain("sink");
    expect(types).toContain("impact");
  });
});

describe("A2 Rule Requirements", () => {
  it("declares tools: true, linguistic", () => {
    expect(rule().requires.tools).toBe(true);
    expect(rule().technique).toBe("linguistic");
  });
});
