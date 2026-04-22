import { describe, it, expect } from "vitest";
import "../index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { isLocation, type Location } from "../../../location.js";

import { buildContext as tp01 } from "../__fixtures__/true-positive-01-approved-by-anthropic.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-stacked-certifications.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-administrator-approved.js";
import { buildContext as tp04 } from "../__fixtures__/true-positive-04-initialize-instructions.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-legit-api-mention.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-self-declared-example.js";
import { buildContext as tn03 } from "../__fixtures__/true-negative-03-plain.js";

function rule() {
  const r = getTypedRuleV2("G2");
  if (!r) throw new Error("G2 rule not registered");
  return r;
}

describe("G2 True Positives", () => {
  it("TP-01 direct vendor endorsement (approved by Anthropic) fires critical", () => {
    const r = rule().analyze(tp01());
    expect(r.length).toBe(1);
    expect(r[0].rule_id).toBe("G2");
    expect(r[0].severity).toBe("critical");
    expect(r[0].chain.confidence).toBeGreaterThanOrEqual(0.60);
  });

  it("TP-02 stacked certification chain aggregates via noisy-OR", () => {
    const r = rule().analyze(tp02());
    expect(r.length).toBe(1);
    expect(r[0].severity === "critical" || r[0].severity === "high").toBe(true);
    const factors = r[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("stacked_claim_corroboration");
  });

  it("TP-03 administrator-approved (in-session authority) fires", () => {
    const r = rule().analyze(tp03());
    expect(r.length).toBe(1);
    expect(r[0].severity === "critical" || r[0].severity === "high").toBe(true);
  });

  it("TP-04 authority claim in initialize.instructions fires with init trust bump", () => {
    const r = rule().analyze(tp04());
    expect(r.length).toBe(1);
    const factors = r[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("initialize_trust_surface");
    // Source should be initialize-field
    const src = r[0].chain.links.find((l) => l.type === "source");
    expect(src).toBeDefined();
    if (src && src.type === "source") {
      expect(src.source_type).toBe("initialize-field");
      if (typeof src.location !== "string") {
        expect((src.location as Location).kind).toBe("initialize");
      }
    }
  });
});

describe("G2 True Negatives", () => {
  it("TN-01 legit Anthropic API mention (no authority verb) does not fire", () => {
    expect(rule().analyze(tn01()).length).toBe(0);
  });

  it("TN-02 self-declared example demoted below floor", () => {
    expect(rule().analyze(tn02()).length).toBe(0);
  });

  it("TN-03 plain descriptive prose does not fire", () => {
    expect(rule().analyze(tn03()).length).toBe(0);
  });
});

describe("G2 Evidence Chain Structure", () => {
  it("every finding has source + propagation + sink + impact", () => {
    const finding = rule().analyze(tp01())[0];
    const types = finding.chain.links.map((l) => l.type);
    expect(types).toContain("source");
    expect(types).toContain("propagation");
    expect(types).toContain("sink");
    expect(types).toContain("impact");
  });

  it("every non-impact link location is a structured Location (v2 contract)", () => {
    const finding = rule().analyze(tp01())[0];
    for (const link of finding.chain.links) {
      if (link.type === "impact") continue;
      expect(
        isLocation(link.location),
        `${link.type} link location must be a Location`,
      ).toBe(true);
      if (isLocation(link.location)) {
        const kind = (link.location as Location).kind;
        expect(kind === "tool" || kind === "initialize").toBe(true);
      }
    }
  });

  it("verification step targets are structured Locations", () => {
    const finding = rule().analyze(tp01())[0];
    for (const step of finding.chain.verification_steps ?? []) {
      expect(isLocation(step.target)).toBe(true);
    }
  });

  it("confidence capped at 0.80 (G2 charter)", () => {
    const finding = rule().analyze(tp02())[0];
    expect(finding.chain.confidence).toBeLessThanOrEqual(0.80);
  });

  it("threat reference cites the Rehberger 2024 authority-assertion research", () => {
    const finding = rule().analyze(tp01())[0];
    expect(finding.chain.threat_reference?.id).toBe("EMBRACE-THE-RED-AUTHORITY-ASSERTION-2024");
  });
});

describe("G2 Rule Requirements", () => {
  it("declares tools: true and linguistic technique", () => {
    expect(rule().requires.tools).toBe(true);
    expect(rule().technique).toBe("linguistic");
  });

  it("returns [] when no tools and no initialize.instructions", () => {
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
