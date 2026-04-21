/**
 * K12 TN-03 — structural test file. Expected: skipped.
 */

import { describe, it } from "vitest";

describe("handler", () => {
  it("returns eval when asked", () => {
    const result = eval("1+1");
    return { result };
  });
});
