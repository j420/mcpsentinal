import { describe, it, expect } from "vitest";
import { NoAuthenticationRequiredRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-http-no-auth.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-ws-no-auth.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-sse-no-auth.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-auth-required.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-no-connection.js";

const rule = new NoAuthenticationRequiredRule();

describe("E1 — No Authentication Required (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags unauthenticated HTTP transport", () => {
      const results = rule.analyze(tp01());
      expect(results.length).toBe(1);
      expect(results[0].severity).toBe("medium");
    });

    it("flags unauthenticated WebSocket transport", () => {
      const results = rule.analyze(tp02());
      expect(results.length).toBe(1);
    });

    it("flags unauthenticated SSE transport", () => {
      const results = rule.analyze(tp03());
      expect(results.length).toBe(1);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("passes when auth_required=true", () => {
      expect(rule.analyze(tn01())).toEqual([]);
    });

    it("skips silently when connection_metadata is null (stdio-only / no connection)", () => {
      expect(rule.analyze(tn02())).toEqual([]);
    });
  });

  describe("chain integrity — v2 contract", () => {
    it("structured Locations + verification targets", () => {
      const results = rule.analyze(tp01());
      for (const r of results) {
        for (const link of r.chain.links) {
          if (link.type === "impact") continue;
          expect(isLocation(link.location)).toBe(true);
        }
        for (const step of r.chain.verification_steps ?? []) {
          expect(isLocation(step.target)).toBe(true);
        }
      }
    });

    it("confidence capped at 0.85, cites MCP-Authorization-2025", () => {
      const results = rule.analyze(tp01());
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.85);
        expect(r.chain.threat_reference?.id).toBe("MCP-Authorization-2025");
      }
    });
  });
});
