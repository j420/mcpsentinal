/**
 * K16 TN-03 — structural test file. The recursive helper has no
 * depth comparison and no visited-set, but the file is detected as a
 * test file via vitest runner import + top-level `it(...)` / `describe(...)`.
 * Expected: skipped (empty findings).
 */

import { describe, it, expect } from "vitest";

function walkRecursive(n: number): number {
  if (n <= 0) return 0;
  return walkRecursive(n - 1) + 1;
}

describe("walkRecursive", () => {
  it("walks bounded test data", () => {
    expect(walkRecursive(3)).toBe(3);
  });
});
