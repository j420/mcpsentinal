/**
 * F7 v2 — functional + chain-integrity tests.
 *
 * Asserts:
 *   - TP fixtures produce at least one F7 finding;
 *   - TN fixtures produce zero findings;
 *   - every link has a structured Location;
 *   - every VerificationStep.target is a Location;
 *   - confidence stays inside (0.30, 0.90];
 *   - confidence factors named in the charter are recorded.
 */

import { describe, it, expect } from "vitest";
import { ExfiltrationChainRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-read-encode-send.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-direct-read-to-send.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-cred-launder-calendar.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-reader-only.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-encoder-only.js";

const rule = new ExfiltrationChainRule();

describe("F7 — Multi-Step Exfiltration Chain (v2)", () => {
  describe("fires (true positives)", () => {
    it("TP-01 read → encode → send produces F7 finding", () => {
      const results = rule.analyze(tp01());
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        expect(r.rule_id).toBe("F7");
        expect(r.severity).toBe("critical");
        expect(r.owasp_category).toBe("MCP04-data-exfiltration");
        expect(r.mitre_technique).toBe("AML.T0057");
      }
    });

    it("TP-02 direct reader→sender without transform step still fires", () => {
      const results = rule.analyze(tp02());
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].rule_id).toBe("F7");
    });

    it("TP-03 friendly-sounding sink is not exempted", () => {
      const results = rule.analyze(tp03());
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].rule_id).toBe("F7");
    });
  });

  describe("does not fire (true negatives)", () => {
    it("TN-01 reader-only server emits zero F7", () => {
      expect(rule.analyze(tn01())).toEqual([]);
    });

    it("TN-02 encoder-only server emits zero F7", () => {
      expect(rule.analyze(tn02())).toEqual([]);
    });
  });

  describe("chain integrity — v2 contract", () => {
    it("TP-01 every link has a structured Location", () => {
      const results = rule.analyze(tp01());
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        const sources = r.chain.links.filter((l) => l.type === "source");
        const sinks = r.chain.links.filter((l) => l.type === "sink");
        expect(sources.length).toBeGreaterThan(0);
        expect(sinks.length).toBeGreaterThan(0);
        for (const link of r.chain.links) {
          if (link.type === "impact") continue;
          expect(isLocation(link.location)).toBe(true);
        }
      }
    });

    it("TP-01 every VerificationStep.target is a Location", () => {
      const results = rule.analyze(tp01());
      for (const r of results) {
        const steps = r.chain.verification_steps ?? [];
        expect(steps.length).toBeGreaterThan(0);
        for (const step of steps) {
          expect(isLocation(step.target)).toBe(true);
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

    it("TP-01 records charter-required confidence factors", () => {
      const results = rule.analyze(tp01());
      expect(results.length).toBeGreaterThan(0);
      const factors = results[0].chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("chain_length");
      expect(factors).toContain("reader_centrality");
      expect(factors).toContain("sender_centrality");
      expect(factors).toContain("transform_step_present");
    });

    it("TP-01 cites MITRE ATLAS AML.T0057 as threat reference", () => {
      const results = rule.analyze(tp01());
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].chain.threat_reference?.id).toBe("MITRE-ATLAS-AML.T0057");
    });
  });
});
