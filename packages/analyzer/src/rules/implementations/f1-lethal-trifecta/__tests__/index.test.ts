/**
 * F1 v2 — functional + chain-integrity tests.
 *
 * Asserts:
 *   - TP fixtures produce at least one F1 finding;
 *   - F1 findings carry rule_id "F1" — scorer keys its 40-point cap on that;
 *   - TN fixtures produce zero F1 findings;
 *   - every link has a structured Location;
 *   - every VerificationStep.target is a Location;
 *   - confidence respects charter cap (≤0.90) and weakest-leg floor;
 *   - companion findings (F2 / F3 / F6) emit with the right rule_id when
 *     the capability-graph / schema-inference pass surfaces those patterns.
 */

import { describe, it, expect } from "vitest";
import { LethalTrifectaRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-classic-trifecta.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-split-across-two-tools.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-cred-plus-fetch.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-utility-only.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-only-two-legs.js";

const rule = new LethalTrifectaRule();

describe("F1 — Lethal Trifecta (v2)", () => {
  describe("fires (true positives)", () => {
    it("TP-01 classic three-tool trifecta produces an F1 finding", () => {
      const results = rule.analyze(tp01());
      const f1 = results.filter((r) => r.rule_id === "F1");
      expect(f1.length).toBeGreaterThan(0);
      for (const r of f1) {
        expect(r.severity).toBe("critical");
        expect(r.owasp_category).toBe("MCP04-data-exfiltration");
        expect(r.mitre_technique).toBe("AML.T0054");
      }
    });

    it("TP-02 trifecta split across two tools still fires F1", () => {
      const results = rule.analyze(tp02());
      const f1 = results.filter((r) => r.rule_id === "F1");
      expect(f1.length).toBeGreaterThan(0);
    });

    it("TP-03 credential + fetch + http_post fires F1", () => {
      const results = rule.analyze(tp03());
      const f1 = results.filter((r) => r.rule_id === "F1");
      expect(f1.length).toBeGreaterThan(0);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("TN-01 utility-only server emits zero F1 findings", () => {
      const results = rule.analyze(tn01());
      expect(results.filter((r) => r.rule_id === "F1").length).toBe(0);
    });

    it("TN-02 only two legs present emits zero F1 findings", () => {
      const results = rule.analyze(tn02());
      expect(results.filter((r) => r.rule_id === "F1").length).toBe(0);
    });
  });

  describe("score cap preservation — scorer keys on rule_id 'F1'", () => {
    it("every F1 finding uses rule_id string 'F1' so the scorer's cap fires", () => {
      const results = rule.analyze(tp01());
      const f1 = results.filter((r) => r.rule_id === "F1");
      expect(f1.length).toBeGreaterThan(0);
      // The scorer in packages/scorer/src/scorer.ts tests
      // `finding.rule_id === "F1"` — the literal must be preserved.
      for (const r of f1) expect(r.rule_id).toBe("F1");
    });
  });

  describe("chain integrity — v2 contract", () => {
    it("TP-01 every link has a structured Location (not a prose string)", () => {
      const results = rule.analyze(tp01());
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
            `${link.type} link location must be a Location, got ${JSON.stringify(link.location)}`,
          ).toBe(true);
        }
      }
    });

    it("TP-01 every VerificationStep.target is a Location", () => {
      const results = rule.analyze(tp01());
      for (const r of results) {
        const steps = r.chain.verification_steps ?? [];
        expect(steps.length).toBeGreaterThan(0);
        for (const step of steps) {
          expect(
            isLocation(step.target),
            `step ${step.step_type} target must be a Location, got ${JSON.stringify(step.target)}`,
          ).toBe(true);
        }
      }
    });

    it("TP-01 confidence capped at 0.90 and above the 0.30 floor", () => {
      const results = rule.analyze(tp01());
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.9);
        expect(r.chain.confidence).toBeGreaterThan(0.3);
      }
    });

    it("TP-01 records all three leg confidence factors", () => {
      const results = rule.analyze(tp01());
      const f1 = results.find((r) => r.rule_id === "F1")!;
      expect(f1).toBeDefined();
      const factors = f1.chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("private_data_leg_confidence");
      expect(factors).toContain("untrusted_content_leg_confidence");
      expect(factors).toContain("external_comms_leg_confidence");
    });
  });

  describe("companion findings (F2 / F3 / F6)", () => {
    it("emits F2/F3/F6 findings with the correct rule_id when the graph surfaces them", () => {
      // All TP contexts exercise the companion emission path via credential-exposure
      // (F3) or unrestricted-access (F2) patterns. We assert that any companion
      // finding produced by F1 carries one of the companion rule ids — never F1 — and
      // that its severity matches the companion-meta table.
      for (const build of [tp01, tp02, tp03]) {
        const results = rule.analyze(build());
        for (const r of results) {
          if (r.rule_id === "F1") continue;
          expect(["F2", "F3", "F6"]).toContain(r.rule_id);
          if (r.rule_id === "F2") expect(r.severity).toBe("critical");
          if (r.rule_id === "F3") expect(r.severity).toBe("critical");
          if (r.rule_id === "F6") expect(r.severity).toBe("high");
        }
      }
    });
  });
});
