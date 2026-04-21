/**
 * K17 TN-05 — structural test file. Expected: skipped.
 */

import { describe, it } from "vitest";

describe("http client", () => {
  it("fetches data", async () => {
    await fetch("http://localhost:3000/api");
  });
});
