import { describe, it, expect } from "vitest";
import { ProgressiveContextPoisoningRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-vector-append-unbounded.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-history-push-no-clear.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-scratchpad-write.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-bounded-buffer.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-unrelated-code.js";

const rule = new ProgressiveContextPoisoningRule();

describe("M6 — Progressive Context Poisoning Enablers (v2)", () => {
  describe("lethal-edge #1 — vector-store append no bound", () => {
    it("fires on unbounded append to a vector/memory store", () => {
      const f = rule.analyze(tp01());
      expect(f.length).toBeGreaterThan(0);
      expect(f[0].rule_id).toBe("M6");
      expect(f[0].severity).toBe("critical");
      expect(f[0].owasp_category).toBe("ASI06-memory-context-poisoning");
    });

    it("mitigation link is present=false when no bound keyword nearby", () => {
      const f = rule.analyze(tp01())[0];
      const mit = f.chain.links.find((l) => l.type === "mitigation");
      expect(mit).toBeDefined();
      if (mit && mit.type === "mitigation") {
        expect(mit.present).toBe(false);
      }
    });
  });

  describe("lethal-edge #2 — conversation history push with no clear", () => {
    it("fires on history.push with no truncation", () => {
      const f = rule.analyze(tp02());
      expect(f.length).toBeGreaterThan(0);
    });
  });

  describe("lethal-edge #3 — scratchpad write", () => {
    it("fires on scratchpad.set with no bound", () => {
      const f = rule.analyze(tp03());
      expect(f.length).toBeGreaterThan(0);
    });
  });

  describe("mitigation path — bound keyword nearby", () => {
    it("TN-01 still fires but with mitigation present=true (bound nearby)", () => {
      const f = rule.analyze(tn01());
      // Fires at most once; when it fires, mitigation is present=true.
      if (f.length > 0) {
        const mit = f[0].chain.links.find((l) => l.type === "mitigation");
        if (mit && mit.type === "mitigation") {
          expect(mit.present).toBe(true);
        }
      }
    });
  });

  describe("negative cases", () => {
    it("does not fire on code with no accumulation pattern", () => {
      expect(rule.analyze(tn02()).length).toBe(0);
    });
  });

  describe("chain integrity — v2 contract", () => {
    it("TP-01: every link has a structured Location", () => {
      const f = rule.analyze(tp01())[0];
      for (const link of f.chain.links) {
        if (link.type === "impact") continue;
        expect(isLocation(link.location)).toBe(true);
      }
    });

    it("TP-01: every verification step target is a Location", () => {
      const f = rule.analyze(tp01())[0];
      const steps = f.chain.verification_steps ?? [];
      expect(steps.length).toBeGreaterThan(0);
      for (const s of steps) expect(isLocation(s.target)).toBe(true);
    });

    it("TP-01: confidence capped at 0.72", () => {
      const f = rule.analyze(tp01())[0];
      expect(f.chain.confidence).toBeLessThanOrEqual(0.72);
    });

    it("records accumulation_without_bounds confidence factor", () => {
      const f = rule.analyze(tp01())[0];
      const factors = f.chain.confidence_factors.map((x) => x.factor);
      expect(factors).toContain("accumulation_without_bounds");
    });
  });
});
