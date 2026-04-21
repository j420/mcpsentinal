/**
 * K11 TN-02 — vitest test file dynamically importing a fixture.
 * Structural test-file detection (vitest import + describe/it blocks)
 * skips the file wholesale.
 */

import { describe, it, expect } from "vitest";

describe("loader", () => {
  it("loads fixture module", async () => {
    const mod = await import("./fixture-server.js");
    expect(mod).toBeDefined();
  });
});
