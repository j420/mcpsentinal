/**
 * I2 stub — asserts registration + empty emission.
 *
 * The canonical production path for I2 findings is the parent rule I1's
 * analyze(). The stub contract tested here: the class is registered,
 * analyze() returns [], technique is 'stub'.
 */

import { describe, it, expect } from "vitest";
import { I2CompanionStub } from "../index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { buildContext } from "../__fixtures__/minimal.js";

describe("I2 — stub companion of I1 (v2)", () => {
  it("is registered in the TypedRuleV2 registry under 'I2'", () => {
    const registered = getTypedRuleV2("I2");
    expect(registered).toBeDefined();
    expect(registered!.id).toBe("I2");
  });

  it("analyze() returns [] — parent rule I1 is the canonical emitter", () => {
    const rule = new I2CompanionStub();
    expect(rule.analyze(buildContext())).toEqual([]);
  });

  it("declares its technique as 'stub' so the coverage dashboard can filter", () => {
    const rule = new I2CompanionStub();
    expect(rule.technique).toBe("stub");
  });
});
