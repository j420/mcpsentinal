// K1 TN — structurally a test file (vitest + describe/it), even without .test suffix.
// Expected: K1 does NOT fire — test files are allowed to use console.*.

import { describe, it, expect } from "vitest";
import express from "express";

describe("tool handler", () => {
  it("accepts a tool call", () => {
    const app = express();
    app.post("/tool", (req, res) => {
      console.log("debugging the test", req.body);
      res.json({ ok: true });
    });
    expect(app).toBeDefined();
  });
});
