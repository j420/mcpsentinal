import { describe, it, expect } from "vitest";
import "../index.js";
import "../../a1-prompt-injection-description/index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { isLocation, type Location } from "../../../location.js";

import { buildContext as tp01 } from "../__fixtures__/true-positive-01-role-override.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-special-token.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-bypass-confirmation.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-plain.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-no-description.js";

function rule() {
  const r = getTypedRuleV2("B5");
  if (!r) throw new Error("B5 rule not registered");
  return r;
}

describe("B5 True Positives", () => {
  it("TP-01 role-override in parameter description fires critical", () => {
    const r = rule().analyze(tp01());
    expect(r.length).toBe(1);
    expect(r[0].severity === "critical" || r[0].severity === "high").toBe(true);
  });
  it("TP-02 LLM special token in parameter description fires", () => {
    expect(rule().analyze(tp02()).length).toBe(1);
  });
  it("TP-03 authority + bypass in parameter description fires", () => {
    const r = rule().analyze(tp03());
    expect(r.length).toBe(1);
  });
});

describe("B5 True Negatives", () => {
  it("TN-01 plain description does not fire", () => {
    expect(rule().analyze(tn01()).length).toBe(0);
  });
  it("TN-02 no description does not fire", () => {
    expect(rule().analyze(tn02()).length).toBe(0);
  });
});

describe("B5 Evidence Chain", () => {
  it("source location is parameter kind", () => {
    const r = rule().analyze(tp01())[0];
    const src = r.chain.links.find((l) => l.type === "source");
    expect(src).toBeDefined();
    if (src && typeof src.location !== "string") {
      expect((src.location as Location).kind).toBe("parameter");
    }
  });
  it("confidence capped at 0.85", () => {
    expect(rule().analyze(tp01())[0].chain.confidence).toBeLessThanOrEqual(0.85);
  });
  it("every link location is structured", () => {
    const r = rule().analyze(tp01())[0];
    for (const l of r.chain.links) {
      if (l.type === "impact") continue;
      expect(isLocation(l.location)).toBe(true);
    }
  });
});
