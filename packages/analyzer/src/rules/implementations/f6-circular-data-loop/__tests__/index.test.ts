/**
 * F6 stub — registration + empty emission contract.
 */

import { describe, it, expect } from "vitest";
import { F6CompanionStub } from "../index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { buildContext } from "../__fixtures__/minimal.js";

describe("F6 — stub companion of F1 (v2)", () => {
  it("is registered in the TypedRuleV2 registry under 'F6'", () => {
    const registered = getTypedRuleV2("F6");
    expect(registered).toBeDefined();
    expect(registered!.id).toBe("F6");
  });

  it("analyze() returns [] — parent rule F1 is the canonical emitter", () => {
    const rule = new F6CompanionStub();
    expect(rule.analyze(buildContext())).toEqual([]);
  });

  it("declares technique 'stub'", () => {
    expect(new F6CompanionStub().technique).toBe("stub");
  });
});
