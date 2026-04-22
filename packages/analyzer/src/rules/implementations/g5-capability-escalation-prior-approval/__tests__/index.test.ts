import { describe, it, expect } from "vitest";
import "../index.js";
import { G5CapabilityEscalationRule } from "../index.js";
import { isLocation, type Location } from "../../../location.js";

import { buildContext as tp01 } from "../__fixtures__/true-positive-01-explicit-prior-approval.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-permission-inheritance.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-assumed-consent.js";
import { buildContext as tp04 } from "../__fixtures__/true-positive-04-session-state.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-plain-tool.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-benign-cross-reference.js";

// Use the class directly to avoid registry coexistence with the legacy
// v1 rule still registered from ai-manipulation-detector.ts (deleted
// by the orchestrator after all wave-5 rules merge).
const rule = new G5CapabilityEscalationRule();

describe("G5 True Positives", () => {
  it("TP-01 explicit prior approval is critical", () => {
    const r = rule.analyze(tp01());
    expect(r.length).toBe(1);
    expect(r[0].rule_id).toBe("G5");
    expect(r[0].severity).toBe("critical");
    expect(r[0].chain.confidence).toBeGreaterThanOrEqual(0.8);
  });

  it("TP-02 permission inheritance fires with adjacency gate satisfied", () => {
    const r = rule.analyze(tp02());
    expect(r.length).toBe(1);
    expect(r[0].severity === "critical" || r[0].severity === "high").toBe(true);
    const factors = r[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("permission_noun_adjacency");
  });

  it("TP-03 assumed consent by absence fires at critical", () => {
    const r = rule.analyze(tp03());
    expect(r.length).toBe(1);
    expect(r[0].severity).toBe("critical");
  });

  it("TP-04 session-state reference fires with multi-category corroboration", () => {
    const r = rule.analyze(tp04());
    expect(r.length).toBe(1);
    const factors = r[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("multi_category_corroboration");
  });
});

describe("G5 True Negatives", () => {
  it("TN-01 plain descriptive prose does not fire", () => {
    expect(rule.analyze(tn01()).length).toBe(0);
  });
  it("TN-02 benign cross-reference without permission noun adjacency does not fire", () => {
    expect(rule.analyze(tn02()).length).toBe(0);
  });
});

describe("G5 Evidence Chain Structure", () => {
  it("every finding has source + propagation + sink + impact", () => {
    const finding = rule.analyze(tp01())[0];
    const types = finding.chain.links.map((l) => l.type);
    expect(types).toContain("source");
    expect(types).toContain("propagation");
    expect(types).toContain("sink");
    expect(types).toContain("impact");
  });

  it("every link location is a tool-kind Location (v2 contract)", () => {
    const finding = rule.analyze(tp01())[0];
    for (const link of finding.chain.links) {
      if (link.type === "impact") continue;
      expect(
        isLocation(link.location),
        `${link.type} link location must be a Location`,
      ).toBe(true);
      if (isLocation(link.location)) {
        expect((link.location as Location).kind).toBe("tool");
      }
    }
  });

  it("verification step targets are structured Locations", () => {
    const finding = rule.analyze(tp01())[0];
    for (const step of finding.chain.verification_steps ?? []) {
      expect(isLocation(step.target)).toBe(true);
    }
  });

  it("confidence capped at 0.82", () => {
    const finding = rule.analyze(tp01())[0];
    expect(finding.chain.confidence).toBeLessThanOrEqual(0.82);
  });

  it("threat reference cites MITRE AML.T0054", () => {
    const finding = rule.analyze(tp01())[0];
    expect(finding.chain.threat_reference?.id).toBe("AML.T0054");
  });

  it("required factors present on every finding", () => {
    const finding = rule.analyze(tp01())[0];
    const factors = finding.chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("prior_approval_phrase_match");
    expect(factors).toContain("noisy_or_base_confidence");
  });
});

describe("G5 Rule Requirements", () => {
  it("declares tools: true and linguistic technique", () => {
    expect(rule.requires.tools).toBe(true);
    expect(rule.technique).toBe("linguistic");
  });

  it("returns [] when no tools", () => {
    const r = rule.analyze({
      server: { id: "e", name: "e", description: null, github_url: null },
      tools: [],
      source_code: null,
      dependencies: [],
      connection_metadata: null,
    });
    expect(r.length).toBe(0);
  });
});
