/**
 * Q6 v2 unit tests.
 */

import { describe, it, expect } from "vitest";
import { AgentIdentityImpersonationRule } from "../index.js";
import { gatherQ6 } from "../gather.js";
import { isLocation, type Location } from "../../../location.js";

import { buildContext as tp01 } from "../__fixtures__/true-positive-01-tool-desc-anthropic.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-tool-desc-official-openai.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-source-serverinfo-literal.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-benign-tool.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-no-context.js";

const rule = new AgentIdentityImpersonationRule();

describe("Q6 — True Positives", () => {
  it("TP-01 'Provided by Anthropic' phrase fires", () => {
    const r = rule.analyze(tp01());
    expect(r.length).toBeGreaterThanOrEqual(1);
    expect(r[0].severity).toBe("critical");
    const g = gatherQ6(tp01());
    expect(g.sites.some((s) => s.vendor === "anthropic")).toBe(true);
  });

  it("TP-02 'official OpenAI MCP' phrase fires", () => {
    const r = rule.analyze(tp02());
    expect(r.length).toBeGreaterThanOrEqual(1);
    const g = gatherQ6(tp02());
    expect(g.sites.some((s) => s.vendor === "openai")).toBe(true);
  });

  it("TP-03 source serverInfo.name with vendor token fires", () => {
    const r = rule.analyze(tp03());
    expect(r.length).toBeGreaterThanOrEqual(1);
    const g = gatherQ6(tp03());
    expect(g.sites.some((s) => s.surface === "source-object-literal")).toBe(true);
  });
});

describe("Q6 — True Negatives", () => {
  it("TN-01 benign tool → 0 findings", () => {
    expect(rule.analyze(tn01()).length).toBe(0);
  });

  it("TN-02 no context (honest refusal) → 0 findings", () => {
    const g = gatherQ6(tn02());
    expect(g.noContextAvailable).toBe(true);
    expect(rule.analyze(tn02()).length).toBe(0);
  });
});

describe("Q6 — Chain integrity", () => {
  it("every chain link carries a structured Location (source or tool)", () => {
    const r = rule.analyze(tp01());
    for (const link of r[0].chain.links) {
      if (link.type === "impact") continue;
      expect(isLocation(link.location)).toBe(true);
      if (isLocation(link.location)) {
        const loc = link.location as Location;
        expect(loc.kind === "source" || loc.kind === "tool").toBe(true);
      }
    }
    for (const step of r[0].chain.verification_steps ?? []) {
      expect(isLocation(step.target)).toBe(true);
    }
  });

  it("confidence is capped at 0.80", () => {
    const r = rule.analyze(tp02());
    expect(r[0].chain.confidence).toBeLessThanOrEqual(0.80);
  });

  it("chain includes source + propagation + sink + impact", () => {
    const r = rule.analyze(tp01());
    const types = new Set(r[0].chain.links.map((l) => l.type));
    expect(types.has("source")).toBe(true);
    expect(types.has("propagation")).toBe(true);
    expect(types.has("sink")).toBe(true);
    expect(types.has("impact")).toBe(true);
  });
});
