import { describe, it, expect } from "vitest";
import { SpecialTokenInjectionRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-chatml-in-name.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-llama-inst-in-desc.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-role-marker-in-param.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-benign-tool.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-role-marker-midline.js";

const rule = new SpecialTokenInjectionRule();

describe("M1 — Special Token Injection in Tool Metadata (v2)", () => {
  describe("lethal-edge #1 — ChatML role delimiter in tool name", () => {
    it("fires when tool name contains <|im_start|>system", () => {
      const findings = rule.analyze(tp01());
      expect(findings.length).toBeGreaterThan(0);
      const first = findings[0];
      expect(first.rule_id).toBe("M1");
      expect(first.severity).toBe("critical");
      expect(first.owasp_category).toBe("ASI01-agent-goal-hijack");
    });

    it("source location is the tool (kind: tool)", () => {
      const f = rule.analyze(tp01())[0];
      const src = f.chain.links.find((l) => l.type === "source")!;
      expect(isLocation(src.location)).toBe(true);
      if (typeof src.location !== "string") {
        expect(src.location.kind).toBe("tool");
      }
    });
  });

  describe("lethal-edge #2 — Llama [INST] block in tool description", () => {
    it("fires when description contains [INST]...[/INST]", () => {
      const f = rule.analyze(tp02());
      expect(f.length).toBeGreaterThan(0);
      // Both [INST] and [/INST] match; at least one finding.
      expect(f.every((r) => r.rule_id === "M1")).toBe(true);
    });
  });

  describe("lethal-edge #4 — conversation-role marker in parameter description", () => {
    it("fires when a parameter description begins with 'System:'", () => {
      const f = rule.analyze(tp03());
      expect(f.length).toBeGreaterThan(0);
      const src = f[0].chain.links.find((l) => l.type === "source")!;
      if (typeof src.location !== "string") {
        expect(src.location.kind).toBe("parameter");
      }
    });
  });

  describe("negative cases", () => {
    it("does not fire on a benign tool with no control tokens", () => {
      expect(rule.analyze(tn01()).length).toBe(0);
    });

    it("does not fire on role-marker-shaped prose mid-sentence (boundary_only)", () => {
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
      for (const step of steps) {
        expect(isLocation(step.target)).toBe(true);
      }
    });

    it("TP-01: confidence capped at 0.88 (charter cap)", () => {
      const f = rule.analyze(tp01())[0];
      expect(f.chain.confidence).toBeLessThanOrEqual(0.88);
    });

    it("TP-01: chain has source, propagation, sink, mitigation, impact links", () => {
      const f = rule.analyze(tp01())[0];
      const types = new Set(f.chain.links.map((l) => l.type));
      expect(types.has("source")).toBe(true);
      expect(types.has("propagation")).toBe(true);
      expect(types.has("sink")).toBe(true);
      expect(types.has("mitigation")).toBe(true);
      expect(types.has("impact")).toBe(true);
    });

    it("records special_token_class_count confidence factor", () => {
      const f = rule.analyze(tp01())[0];
      const factors = f.chain.confidence_factors.map((x) => x.factor);
      expect(factors).toContain("special_token_class_count");
    });
  });
});
