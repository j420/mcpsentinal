/**
 * I13 v2 — functional + chain-integrity tests + score-cap preservation.
 *
 * Asserts:
 *   - TP fixtures fire I13 with rule_id "I13" (exact string — scorer
 *     keys on this to apply the 40-point cap);
 *   - TN fixtures (single-server, incomplete trifecta) do NOT fire;
 *   - every link carries a structured Location;
 *   - every VerificationStep.target is a Location;
 *   - confidence ≤ 0.90 (charter cap).
 */

import { describe, it, expect } from "vitest";
import { CrossConfigLethalTrifectaRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-three-server-split.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-two-server-split.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-credential-plus-scrape-plus-send.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-single-server.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-two-server-only-two-legs.js";

const rule = new CrossConfigLethalTrifectaRule();

describe("I13 — Cross-Config Lethal Trifecta (v2)", () => {
  describe("fires (true positives)", () => {
    it("TP-01 three-server split (DB / web / webhook) produces I13 finding", () => {
      const results = rule.analyze(tp01());
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        expect(r.severity).toBe("critical");
        expect(r.owasp_category).toBe("MCP04-data-exfiltration");
        expect(r.mitre_technique).toBe("AML.T0054");
      }
    });

    it("TP-02 two-server split (file+web / egress) fires I13", () => {
      const results = rule.analyze(tp02());
      expect(results.length).toBeGreaterThan(0);
    });

    it("TP-03 credential + scrape + egress fires I13", () => {
      const results = rule.analyze(tp03());
      expect(results.length).toBeGreaterThan(0);
    });
  });

  describe("score cap preservation — scorer keys on rule_id 'I13'", () => {
    it("every I13 finding uses literal 'I13' so scorer.ts cap fires", () => {
      // packages/scorer/src/scorer.ts line 254 and 269:
      //   finding.rule_id === "F1" || finding.rule_id === "I13"
      // The literal string MUST be preserved across migrations.
      const results = rule.analyze(tp01());
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) expect(r.rule_id).toBe("I13");
    });
  });

  describe("honest-refusal (true negatives)", () => {
    it("TN-01 single-server context (no multi_server_tools) emits zero findings", () => {
      expect(rule.analyze(tn01())).toEqual([]);
    });

    it("TN-02 two servers with only benign capabilities (no trifecta) emits zero findings", () => {
      expect(rule.analyze(tn02())).toEqual([]);
    });
  });

  describe("per-server contribution mapping", () => {
    it("TP-01 records each server's contribution in the chain", () => {
      const results = rule.analyze(tp01());
      const r = results[0];
      const propRationale = r.chain.links
        .filter((l) => l.type === "propagation")
        .map((l) => (l as { observed: string }).observed)
        .join(" ");
      // The propagation link's observed text reports the per-server distribution.
      expect(propRationale).toMatch(/server-a-db|server-b-web|server-c-webhook/);
    });

    it("TP-02 two-server finding enumerates both servers", () => {
      const results = rule.analyze(tp02());
      const r = results[0];
      const propLink = r.chain.links.find((l) => l.type === "propagation");
      expect(propLink).toBeDefined();
      const observed = (propLink as { observed: string }).observed;
      expect(observed).toMatch(/server-a-fileweb/);
      expect(observed).toMatch(/server-b-egress/);
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

      it(`${fx.name} → every VerificationStep.target is a Location`, () => {
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

      it(`${fx.name} → confidence ≤ 0.90 (charter cap)`, () => {
        const results = rule.analyze(fx.build());
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.9);
          expect(r.chain.confidence).toBeGreaterThan(0.3);
        }
      });

      it(`${fx.name} → cites Willison-Lethal-Trifecta-2025`, () => {
        const results = rule.analyze(fx.build());
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("Willison-Lethal-Trifecta-2025");
        }
      });
    }
  });
});
