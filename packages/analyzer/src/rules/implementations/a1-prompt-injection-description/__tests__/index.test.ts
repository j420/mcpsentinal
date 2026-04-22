import { describe, it, expect } from "vitest";
import "../index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { isLocation, type Location } from "../../../location.js";

import { buildContext as tp01 } from "../__fixtures__/true-positive-01-role-override.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-special-token.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-authority-and-bypass.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-plain-tool.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-single-imperative.js";

function rule() {
  const r = getTypedRuleV2("A1");
  if (!r) throw new Error("A1 rule not registered");
  return r;
}

describe("A1 True Positives", () => {
  it("TP-01 role override + exfiltration directive is critical", () => {
    const r = rule().analyze(tp01());
    expect(r.length).toBe(1);
    expect(r[0].rule_id).toBe("A1");
    expect(r[0].severity).toBe("critical");
    expect(r[0].chain.confidence).toBeGreaterThanOrEqual(0.8);
  });

  it("TP-02 LLM special token fires even without catalogue phrases", () => {
    const r = rule().analyze(tp02());
    expect(r.length).toBe(1);
    const factors = r[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("in_band_control_token");
  });

  it("TP-03 authority claim + confirmation bypass corroborate", () => {
    const r = rule().analyze(tp03());
    expect(r.length).toBe(1);
    expect(r[0].severity === "critical" || r[0].severity === "high").toBe(true);
    const factors = r[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("multi_signal_corroboration");
  });
});

describe("A1 True Negatives", () => {
  it("TN-01 plain descriptive prose does not fire", () => {
    expect(rule().analyze(tn01()).length).toBe(0);
  });
  it("TN-02 single imperative 'always returns' does not fire", () => {
    expect(rule().analyze(tn02()).length).toBe(0);
  });
});

describe("A1 Evidence Chain Structure", () => {
  it("every finding has source + propagation + sink + impact", () => {
    const finding = rule().analyze(tp01())[0];
    const types = finding.chain.links.map((l) => l.type);
    expect(types).toContain("source");
    expect(types).toContain("propagation");
    expect(types).toContain("sink");
    expect(types).toContain("impact");
  });

  it("every link location is a structured Location (v2 contract)", () => {
    const finding = rule().analyze(tp01())[0];
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
    const finding = rule().analyze(tp01())[0];
    for (const step of finding.chain.verification_steps ?? []) {
      expect(isLocation(step.target)).toBe(true);
    }
  });

  it("confidence capped at 0.85", () => {
    const finding = rule().analyze(tp01())[0];
    expect(finding.chain.confidence).toBeLessThanOrEqual(0.85);
  });

  it("threat reference cites MITRE AML.T0054", () => {
    const finding = rule().analyze(tp01())[0];
    expect(finding.chain.threat_reference?.id).toBe("AML.T0054");
  });
});

describe("A1 Rule Requirements", () => {
  it("declares tools: true and linguistic technique", () => {
    expect(rule().requires.tools).toBe(true);
    expect(rule().technique).toBe("linguistic");
  });

  it("returns [] when no tools", () => {
    const r = rule().analyze({
      server: { id: "e", name: "e", description: null, github_url: null },
      tools: [],
      source_code: null,
      dependencies: [],
      connection_metadata: null,
    });
    expect(r.length).toBe(0);
  });
});
