/**
 * F2 stub — asserts registration + empty emission.
 *
 * The canonical production path for F2 findings is F1's
 * buildCompanionFinding(). A separate test in F1's suite already asserts
 * the companion emission end-to-end. Here we assert only the stub
 * contract: the class is registered, analyze() returns [].
 */

import { describe, it, expect } from "vitest";
import { F2CompanionStub } from "../index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { buildContext } from "../__fixtures__/minimal.js";

describe("F2 — stub companion of F1 (v2)", () => {
  it("is registered in the TypedRuleV2 registry under 'F2'", () => {
    const registered = getTypedRuleV2("F2");
    expect(registered).toBeDefined();
    expect(registered!.id).toBe("F2");
  });

  it("analyze() returns [] — parent rule F1 is the canonical emitter", () => {
    const rule = new F2CompanionStub();
    expect(rule.analyze(buildContext())).toEqual([]);
  });

  it("declares its technique as 'stub' so the coverage dashboard can filter", () => {
    const rule = new F2CompanionStub();
    expect(rule.technique).toBe("stub");
  });
});
