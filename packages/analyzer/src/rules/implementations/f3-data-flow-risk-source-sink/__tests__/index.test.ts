/**
 * F3 stub — registration + empty emission contract.
 */

import { describe, it, expect } from "vitest";
import { F3CompanionStub } from "../index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { buildContext } from "../__fixtures__/minimal.js";

describe("F3 — stub companion of F1 (v2)", () => {
  it("is registered in the TypedRuleV2 registry under 'F3'", () => {
    const registered = getTypedRuleV2("F3");
    expect(registered).toBeDefined();
    expect(registered!.id).toBe("F3");
  });

  it("analyze() returns [] — parent rule F1 is the canonical emitter", () => {
    const rule = new F3CompanionStub();
    expect(rule.analyze(buildContext())).toEqual([]);
  });

  it("declares technique 'stub'", () => {
    expect(new F3CompanionStub().technique).toBe("stub");
  });
});
