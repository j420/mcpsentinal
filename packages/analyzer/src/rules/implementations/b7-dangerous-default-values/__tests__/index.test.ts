import { describe, it, expect } from "vitest";
import "../index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { isLocation, type Location } from "../../../location.js";

import { buildContext as tp01 } from "../__fixtures__/true-positive-01-overwrite-true.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-recursive-disable-ssl.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-path-root.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-safe-defaults.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-no-defaults.js";

function rule() {
  const r = getTypedRuleV2("B7");
  if (!r) throw new Error("B7 rule not registered");
  return r;
}

describe("B7 True Positives", () => {
  it("TP-01 overwrite=true fires", () => expect(rule().analyze(tp01()).length).toBe(1));
  it("TP-02 recursive=true + disable_ssl_verify=true fires (2 findings)", () => {
    expect(rule().analyze(tp02()).length).toBe(2);
  });
  it("TP-03 directory='/' fires", () => expect(rule().analyze(tp03()).length).toBe(1));
});

describe("B7 True Negatives", () => {
  it("TN-01 safe defaults do not fire", () =>
    expect(rule().analyze(tn01()).length).toBe(0));
  it("TN-02 no defaults (required params) do not fire", () =>
    expect(rule().analyze(tn02()).length).toBe(0));
});

describe("B7 Evidence Chain", () => {
  it("source location is parameter kind", () => {
    const r = rule().analyze(tp01())[0];
    const src = r.chain.links.find((l) => l.type === "source");
    if (src && typeof src.location !== "string") {
      expect((src.location as Location).kind).toBe("parameter");
    }
  });
  it("confidence capped at 0.90 and severity high", () => {
    const r = rule().analyze(tp01())[0];
    expect(r.chain.confidence).toBeLessThanOrEqual(0.90);
    expect(r.severity).toBe("high");
  });
  it("structured locations on every link", () => {
    const r = rule().analyze(tp01())[0];
    for (const l of r.chain.links) {
      if (l.type === "impact") continue;
      expect(isLocation(l.location)).toBe(true);
    }
  });
});
