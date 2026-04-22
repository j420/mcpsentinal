/**
 * I1 v2 — functional + chain-integrity tests.
 *
 * Asserts each CHARTER.md lethal edge case and the v2 contract:
 *   - TP fixtures produce at least one I1 finding with rule_id "I1";
 *   - TN fixtures produce zero I1 findings;
 *   - every evidence link carries a structured Location (not prose);
 *   - every VerificationStep.target is a Location;
 *   - confidence respects the charter cap (≤0.85) and floor (≥0.60).
 */

import { describe, it, expect } from "vitest";
import { AnnotationDeceptionRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-readonly-with-delete-param.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-self-contradicting-hints.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-description-destructive-verb.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-honest-readonly.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-destructive-with-destructive-hint.js";

const rule = new AnnotationDeceptionRule();

describe("I1 — Annotation Deception (v2)", () => {
  describe("fires (true positives)", () => {
    it("TP-01 readOnlyHint: true with destructive parameter name fires I1", () => {
      const results = rule.analyze(tp01());
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        expect(r.rule_id).toBe("I1");
        expect(r.severity).toBe("critical");
        expect(r.owasp_category).toBe("MCP06-excessive-permissions");
        expect(r.mitre_technique).toBe("AML.T0054");
      }
    });

    it("TP-01 records both parameter-name and (likely) schema-inference signals", () => {
      const results = rule.analyze(tp01());
      const factors = results.flatMap((r) => r.chain.confidence_factors.map((f) => f.factor));
      expect(factors).toContain("annotation_contradiction");
      expect(factors).toContain("destructive_signal_source");
    });

    it("TP-02 self-contradicting hints (readOnlyHint + destructiveHint both true) fires I1", () => {
      const results = rule.analyze(tp02());
      expect(results.length).toBeGreaterThan(0);
      const f = results[0];
      const factors = f.chain.confidence_factors.map((x) => x.factor);
      expect(factors).toContain("annotation_contradiction");
      // The rationale should mention the mutual-exclusion.
      const rationale = f.chain.confidence_factors
        .find((x) => x.factor === "annotation_contradiction")?.rationale ?? "";
      expect(rationale).toMatch(/mutually exclusive/);
    });

    it("TP-03 destructive verb in description only (no matching parameter name) fires I1", () => {
      const results = rule.analyze(tp03());
      expect(results.length).toBeGreaterThan(0);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("TN-01 honest read-only tool emits zero I1 findings", () => {
      expect(rule.analyze(tn01())).toEqual([]);
    });

    it("TN-02 destructive tool with destructiveHint: true (no readOnlyHint) emits zero I1 findings", () => {
      expect(rule.analyze(tn02())).toEqual([]);
    });
  });

  describe("chain integrity — v2 contract", () => {
    const fixtures: Array<{ name: string; build: () => ReturnType<typeof tp01> }> = [
      { name: "TP-01", build: tp01 },
      { name: "TP-02", build: tp02 },
      { name: "TP-03", build: tp03 },
    ];

    for (const fx of fixtures) {
      it(`${fx.name} → every non-impact link has a structured Location`, () => {
        const results = rule.analyze(fx.build());
        expect(results.length).toBeGreaterThan(0);
        for (const r of results) {
          const sources = r.chain.links.filter((l) => l.type === "source");
          const sinks = r.chain.links.filter((l) => l.type === "sink");
          expect(sources.length).toBeGreaterThan(0);
          expect(sinks.length).toBeGreaterThan(0);
          for (const link of r.chain.links) {
            if (link.type === "impact") continue;
            expect(
              isLocation(link.location),
              `${fx.name} ${link.type} link location must be a Location, got ${JSON.stringify(link.location)}`,
            ).toBe(true);
          }
        }
      });

      it(`${fx.name} → every VerificationStep.target is a structured Location`, () => {
        const results = rule.analyze(fx.build());
        for (const r of results) {
          const steps = r.chain.verification_steps ?? [];
          expect(steps.length).toBeGreaterThan(0);
          for (const step of steps) {
            expect(
              isLocation(step.target),
              `${fx.name} step ${step.step_type} target must be a Location, got ${JSON.stringify(step.target)}`,
            ).toBe(true);
          }
        }
      });

      it(`${fx.name} → confidence in [0.60, 0.85]`, () => {
        const results = rule.analyze(fx.build());
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.85);
          expect(r.chain.confidence).toBeGreaterThanOrEqual(0.6);
        }
      });

      it(`${fx.name} → cites Invariant-Labs-Annotation-Deception-2025`, () => {
        const results = rule.analyze(fx.build());
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("Invariant-Labs-Annotation-Deception-2025");
        }
      });
    }
  });
});
