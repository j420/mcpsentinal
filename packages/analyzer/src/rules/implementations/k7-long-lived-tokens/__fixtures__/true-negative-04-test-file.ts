/**
 * K7 TN-04 — structural test file. Even though the body contains an
 * excessive expiry, the file is skipped via two-signal test-file
 * detection (vitest import + top-level describe/it).
 */

import { describe, it, expect } from "vitest";
import jwt from "jsonwebtoken";

describe("token issuance", () => {
  it("works in the test", () => {
    const t = jwt.sign({ x: 1 }, "s", { expiresIn: "365d" });
    expect(t).toBeTruthy();
  });
});
