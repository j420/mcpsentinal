/**
 * K4 TN-03 — structurally-identified test file. Detection uses BOTH
 * signals (top-level describe + runner import), so even though `db.
 * deleteAll()` appears inside the test body, no finding is emitted.
 */

import { describe, it, expect } from "vitest";

const db = { deleteAll(_opts: { table: string }): void {} };

describe("cleanup", () => {
  it("wipes the test table", () => {
    db.deleteAll({ table: "test_data" });
    expect(true).toBe(true);
  });
});
