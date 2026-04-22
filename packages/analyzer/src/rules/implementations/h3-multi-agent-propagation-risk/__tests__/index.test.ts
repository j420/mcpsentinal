/**
 * H3 v2 — functional + chain-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { MultiAgentPropagationRiskRule } from "../index.js";
import { isLocation } from "../../../location.js";

import { buildContext as tp1 } from "../__fixtures__/true-positive-01-agent-output-parameter.js";
import { buildContext as tp2 } from "../__fixtures__/true-positive-02-shared-memory-writer.js";
import { buildContext as tp3 } from "../__fixtures__/true-positive-03-dual-role.js";
import { buildContext as tn1 } from "../__fixtures__/true-negative-01-sanitization-declared.js";
import { buildContext as tn2 } from "../__fixtures__/true-negative-02-single-agent-tool.js";

const rule = new MultiAgentPropagationRiskRule();

describe("H3 — Multi-Agent Propagation Risk (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags agent_output parameter (agent-input sink)", () => {
      const results = rule.analyze(tp1());
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        expect(r.rule_id).toBe("H3");
        expect(r.severity).toBe("high");
      }
      const factors = results.flatMap((r) => r.chain.confidence_factors.map((f) => f.factor));
      expect(factors).toContain("propagation_sink_class");
    });

    it("flags shared-memory-writer (vector-store write action)", () => {
      const results = rule.analyze(tp2());
      expect(results.length).toBeGreaterThan(0);
      const rationales = results.flatMap((r) => r.chain.confidence_factors.map((f) => f.rationale)).join("\n");
      expect(rationales).toContain("shared-memory-writer");
    });

    it("flags dual-role tool with the dual_role_amplifier factor", () => {
      const results = rule.analyze(tp3());
      expect(results.length).toBeGreaterThan(0);
      const factors = results.flatMap((r) => r.chain.confidence_factors.map((f) => f.factor));
      expect(factors).toContain("dual_role_amplifier");
    });
  });

  describe("does not fire (true negatives)", () => {
    it("skips a tool that declares sanitization in its description", () => {
      expect(rule.analyze(tn1())).toEqual([]);
    });

    it("skips a single-agent tool with no inter-agent vocabulary", () => {
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

      it(`${label} → confidence capped at 0.75, floored above 0.30`, () => {
        const results = rule.analyze(build());
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.75);
          expect(r.chain.confidence).toBeGreaterThan(0.3);
        }
      });

      it(`${label} → cites OWASP-ASI07-Insecure-Inter-Agent-Comms`, () => {
        const results = rule.analyze(build());
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("OWASP-ASI07-Insecure-Inter-Agent-Comms");
        }
      });
    }
  });
});
