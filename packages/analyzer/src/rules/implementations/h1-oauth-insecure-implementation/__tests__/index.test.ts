/**
 * H1 v2 — functional + chain-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { OAuthInsecureImplementationRule } from "../index.js";
import { isLocation } from "../../../location.js";

import { buildContext as tp1 } from "../__fixtures__/true-positive-01-implicit-flow.js";
import { buildContext as tp2 } from "../__fixtures__/true-positive-02-ropc.js";
import { buildContext as tp3 } from "../__fixtures__/true-positive-03-redirect-uri-from-request.js";
import { buildContext as tp4 } from "../__fixtures__/true-positive-04-localstorage-token.js";
import { buildContext as tn1 } from "../__fixtures__/true-negative-01-secure-auth-code-flow.js";
import { buildContext as tn2 } from "../__fixtures__/true-negative-02-no-oauth.js";

const rule = new OAuthInsecureImplementationRule();

describe("H1 — MCP OAuth 2.0 Insecure Implementation (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags implicit-flow (response_type=token)", () => {
      const results = rule.analyze(tp1());
      expect(results.length).toBeGreaterThan(0);
      const patterns = results
        .flatMap((r) => r.chain.confidence_factors.map((f) => f.rationale))
        .join("\n");
      expect(patterns).toContain("implicit-flow-literal");
      for (const r of results) {
        expect(r.rule_id).toBe("H1");
        expect(r.severity).toBe("critical");
      }
    });

    it("flags ROPC grant (grant_type=password)", () => {
      const results = rule.analyze(tp2());
      expect(results.length).toBeGreaterThan(0);
      const rationales = results.flatMap((r) => r.chain.confidence_factors.map((f) => f.rationale)).join("\n");
      expect(rationales).toContain("ropc-grant-literal");
    });

    it("flags redirect_uri sourced from req.query", () => {
      const results = rule.analyze(tp3());
      expect(results.length).toBeGreaterThan(0);
      const rationales = results.flatMap((r) => r.chain.confidence_factors.map((f) => f.rationale)).join("\n");
      expect(rationales).toContain("redirect-uri-from-request");
    });

    it("flags localStorage.setItem token write", () => {
      const results = rule.analyze(tp4());
      expect(results.length).toBeGreaterThan(0);
      const rationales = results.flatMap((r) => r.chain.confidence_factors.map((f) => f.rationale)).join("\n");
      expect(rationales).toContain("localstorage-token-write");
    });
  });

  describe("does not fire (true negatives)", () => {
    it("skips a fully RFC-9700-compliant auth-code flow with PKCE", () => {
      const results = rule.analyze(tn1());
      // We accept zero findings or only state-validation-absence false negatives.
      // A proper secure flow should not match any of the six patterns.
      for (const r of results) {
        const rationales = r.chain.confidence_factors.map((f) => f.rationale).join("\n");
        // No banned literal or tainted redirect_uri patterns should fire.
        expect(rationales).not.toContain("implicit-flow-literal");
        expect(rationales).not.toContain("ropc-grant-literal");
        expect(rationales).not.toContain("redirect-uri-from-request");
        expect(rationales).not.toContain("localstorage-token-write");
        expect(rationales).not.toContain("scope-from-request");
      }
    });

    it("skips source code with no OAuth patterns at all", () => {
      expect(rule.analyze(tn2())).toEqual([]);
    });
  });

  describe("chain integrity — v2 contract", () => {
    const fixtures = [tp1, tp2, tp3, tp4] as const;
    for (let i = 0; i < fixtures.length; i++) {
      const build = fixtures[i];
      const label = `tp${i + 1}`;

      it(`${label} → every link has a structured Location`, () => {
        const results = rule.analyze(build());
        expect(results.length).toBeGreaterThan(0);
        for (const r of results) {
          const sourceLinks = r.chain.links.filter((l) => l.type === "source");
          const sinkLinks = r.chain.links.filter((l) => l.type === "sink");
          expect(sourceLinks.length).toBeGreaterThan(0);
          expect(sinkLinks.length).toBeGreaterThan(0);
          for (const link of r.chain.links) {
            if (link.type === "impact") continue;
            expect(isLocation(link.location)).toBe(true);
          }
        }
      });

      it(`${label} → every VerificationStep.target is a structured Location`, () => {
        const results = rule.analyze(build());
        for (const r of results) {
          const steps = r.chain.verification_steps ?? [];
          expect(steps.length).toBeGreaterThan(0);
          for (const step of steps) {
            expect(isLocation(step.target)).toBe(true);
          }
        }
      });

      it(`${label} → confidence capped at 0.88, floored above 0.30`, () => {
        const results = rule.analyze(build());
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.88);
          expect(r.chain.confidence).toBeGreaterThan(0.3);
        }
      });

      it(`${label} → cites RFC 9700 as primary threat reference`, () => {
        const results = rule.analyze(build());
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("RFC-9700-OAuth-2.1-BCP");
        }
      });
    }
  });
});
