/**
 * K6 TN-03 — structural test file carrying an `admin` scope for test
 * setup. Two-signal detection fires (vitest import + top-level describe
 * call). Expected: whole file skipped.
 */

import { describe, it, expect } from "vitest";

describe("oauth integration", () => {
  it("uses admin scope in the test client", () => {
    const cfg = {
      client_id: "test-client",
      token_endpoint: "http://localhost/token",
      scope: "*",
    };
    expect(cfg.scope).toBe("*");
  });
});
