import { describe, it, expect } from "vitest";
import "../index.js";
import { H2InitFieldInjectionRule } from "../index.js";
import { isLocation, type Location } from "../../../location.js";

import { buildContext as tp01 } from "../__fixtures__/true-positive-01-special-token-in-name.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-authority-instructions.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-base64-in-instructions.js";
import { buildContext as tp04 } from "../__fixtures__/true-positive-04-unicode-in-name.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-null-metadata.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-benign-instructions.js";
import { buildContext as tn03 } from "../__fixtures__/true-negative-03-short-non-semver-version.js";

// Use the class directly to avoid registry coexistence with the legacy
// v1 rule still registered from ai-manipulation-detector.ts (deleted
// by the orchestrator after all wave-5 rules merge).
const rule = new H2InitFieldInjectionRule();

describe("H2 True Positives", () => {
  it("TP-01 LLM special token in server.name fires at critical", () => {
    const r = rule.analyze(tp01());
    expect(r.length).toBeGreaterThanOrEqual(1);
    const nameFinding = r.find((f) => {
      const src = f.chain.links.find((l) => l.type === "source");
      return (
        src !== undefined &&
        isLocation(src.location) &&
        (src.location as Location).kind === "initialize" &&
        (src.location as Extract<Location, { kind: "initialize" }>).field === "server_name"
      );
    });
    expect(nameFinding).toBeDefined();
    expect(nameFinding!.severity).toBe("critical");
    const factors = nameFinding!.chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("llm_special_token_in_initialize");
  });

  it("TP-02 authority directive in instructions is critical", () => {
    const r = rule.analyze(tp02());
    const instr = r.find((f) => {
      const src = f.chain.links.find((l) => l.type === "source");
      return (
        src !== undefined &&
        isLocation(src.location) &&
        (src.location as Extract<Location, { kind: "initialize" }>).field === "instructions"
      );
    });
    expect(instr).toBeDefined();
    expect(instr!.severity).toBe("critical");
    const factors = instr!.chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("multi_kind_corroboration");
  });

  it("TP-03 base64 hidden payload in instructions fires", () => {
    const r = rule.analyze(tp03());
    const instr = r.find((f) => {
      const src = f.chain.links.find((l) => l.type === "source");
      return (
        src !== undefined &&
        isLocation(src.location) &&
        (src.location as Extract<Location, { kind: "initialize" }>).field === "instructions"
      );
    });
    expect(instr).toBeDefined();
    const factors = instr!.chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("base64_hidden_payload_in_initialize");
  });

  it("TP-04 Unicode RTL override in server.name fires", () => {
    const r = rule.analyze(tp04());
    const nameFinding = r.find((f) => {
      const src = f.chain.links.find((l) => l.type === "source");
      return (
        src !== undefined &&
        isLocation(src.location) &&
        (src.location as Extract<Location, { kind: "initialize" }>).field === "server_name"
      );
    });
    expect(nameFinding).toBeDefined();
    const factors = nameFinding!.chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("unicode_control_in_initialize");
  });
});

describe("H2 True Negatives", () => {
  it("TN-01 null initialize_metadata produces zero findings (silent skip)", () => {
    expect(rule.analyze(tn01()).length).toBe(0);
  });
  it("TN-02 legitimate initialize metadata produces zero findings", () => {
    expect(rule.analyze(tn02()).length).toBe(0);
  });
  it('TN-03 short non-semver server_version="2.0" produces zero findings (locks version-shape FP fix)', () => {
    expect(rule.analyze(tn03()).length).toBe(0);
  });
});

describe("H2 Evidence Chain Structure", () => {
  it("every finding has source + propagation + sink + impact", () => {
    const finding = rule.analyze(tp02())[0];
    const types = finding.chain.links.map((l) => l.type);
    expect(types).toContain("source");
    expect(types).toContain("propagation");
    expect(types).toContain("sink");
    expect(types).toContain("impact");
  });

  it("every non-impact link location is an initialize-kind Location", () => {
    const finding = rule.analyze(tp02())[0];
    for (const link of finding.chain.links) {
      if (link.type === "impact") continue;
      expect(
        isLocation(link.location),
        `${link.type} link location must be a Location`,
      ).toBe(true);
      if (isLocation(link.location)) {
        expect((link.location as Location).kind).toBe("initialize");
      }
    }
  });

  it("verification step targets are initialize-kind Locations", () => {
    const finding = rule.analyze(tp02())[0];
    for (const step of finding.chain.verification_steps ?? []) {
      expect(isLocation(step.target)).toBe(true);
      if (isLocation(step.target)) {
        expect((step.target as Location).kind).toBe("initialize");
      }
    }
  });

  it("confidence capped at 0.88", () => {
    const finding = rule.analyze(tp02())[0];
    expect(finding.chain.confidence).toBeLessThanOrEqual(0.88);
  });

  it("threat reference cites the MCP 2024-11-05 spec", () => {
    const finding = rule.analyze(tp02())[0];
    expect(finding.chain.threat_reference?.id).toBe("MCP-SPEC-2024-11-05");
  });

  it("required factors present on every finding", () => {
    const finding = rule.analyze(tp02())[0];
    const factors = finding.chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("init_field_signal_match");
    expect(factors).toContain("noisy_or_base_confidence");
  });
});

describe("H2 Rule Requirements", () => {
  it("declares composite technique (phrase + token + unicode + entropy)", () => {
    expect(rule.technique).toBe("composite");
  });

  it("returns [] when context has no init fields of interest", () => {
    const r = rule.analyze({
      server: { id: "e", name: "plain", description: null, github_url: null },
      tools: [],
      source_code: null,
      dependencies: [],
      connection_metadata: null,
    });
    expect(r.length).toBe(0);
  });
});
