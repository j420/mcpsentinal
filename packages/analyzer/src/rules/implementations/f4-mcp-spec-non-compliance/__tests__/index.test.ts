/**
 * F4 v2 — functional + chain-integrity tests.
 *
 * Each fixture exports a buildContext() that returns an AnalysisContext
 * describing a tools/list response. The rule analyses the context and we
 * assert:
 *
 *   - TP fixtures produce at least one finding;
 *   - TN fixtures produce zero findings;
 *   - every finding has a source link and a sink link with structured
 *     Locations (not prose strings);
 *   - every VerificationStep.target is a Location, not a string;
 *   - confidence is in [0.30, 0.75] (charter cap);
 *   - the threat reference is OWASP-MCP07-Insecure-Config (charter primary cite).
 */

import { describe, it, expect } from "vitest";
import { McpSpecNonComplianceRule } from "../index.js";
import { isLocation } from "../../../location.js";

import { buildContext as tp1 } from "../__fixtures__/true-positive-01-empty-name.js";
import { buildContext as tp2 } from "../__fixtures__/true-positive-02-missing-description.js";
import { buildContext as tp3 } from "../__fixtures__/true-positive-03-missing-input-schema.js";
import { buildContext as tn1 } from "../__fixtures__/true-negative-01-complete-tool.js";
import { buildContext as tn2 } from "../__fixtures__/true-negative-02-empty-properties.js";

const rule = new McpSpecNonComplianceRule();

describe("F4 — MCP Spec Non-Compliance (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags empty tool name as a required-field violation", () => {
      const results = rule.analyze(tp1());
      expect(results.length).toBeGreaterThan(0);
      const factors = results.flatMap((r) => r.chain.confidence_factors.map((f) => f.factor));
      expect(factors).toContain("required_field_missing");
      for (const r of results) {
        expect(r.rule_id).toBe("F4");
        expect(r.severity).toBe("low");
      }
    });

    it("flags missing description as a recommended-field violation", () => {
      const results = rule.analyze(tp2());
      expect(results.length).toBeGreaterThan(0);
      const factors = results.flatMap((r) => r.chain.confidence_factors.map((f) => f.factor));
      expect(factors).toContain("recommended_field_missing");
    });

    it("flags missing inputSchema (null) but not empty-properties inputSchema", () => {
      const results = rule.analyze(tp3());
      expect(results.length).toBeGreaterThan(0);
      const observations = results.map((r) => {
        const link = r.chain.links.find((l) => l.type === "source");
        return link?.type === "source" ? link.observed : "";
      });
      expect(observations.some((o) => o.includes("inputSchema"))).toBe(true);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("skips a complete, spec-compliant tool", () => {
      expect(rule.analyze(tn1())).toEqual([]);
    });

    it("accepts an empty-properties inputSchema as a legitimate zero-parameter tool", () => {
      expect(rule.analyze(tn2())).toEqual([]);
    });
  });

  describe("chain integrity — v2 contract", () => {
    const fixtures = [tp1, tp2, tp3] as const;
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
            expect(
              isLocation(link.location),
              `${label} ${link.type} link location must be a structured Location`,
            ).toBe(true);
          }
        }
      });

      it(`${label} → every VerificationStep.target is a structured Location`, () => {
        const results = rule.analyze(build());
        for (const r of results) {
          const steps = r.chain.verification_steps ?? [];
          expect(steps.length).toBeGreaterThan(0);
          for (const step of steps) {
            expect(
              isLocation(step.target),
              `${label} step ${step.step_type} target must be a Location`,
            ).toBe(true);
          }
        }
      });

      it(`${label} → confidence capped at 0.75, floored above 0.30`, () => {
        const results = rule.analyze(build());
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.75);
          expect(r.chain.confidence).toBeGreaterThan(0.3);
        }
      });

      it(`${label} → cites OWASP-MCP07-Insecure-Config`, () => {
        const results = rule.analyze(build());
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("OWASP-MCP07-Insecure-Config");
        }
      });
    }
  });
});
