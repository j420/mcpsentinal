import { describe, it, expect } from "vitest";
import "../index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { isLocation, type Location } from "../../../location.js";

import { buildContext as tp01 } from "../__fixtures__/true-positive-01-returns-jsonrpc-prose.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-literal-envelope.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-returns-mcp-protocol.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-plain-json.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-educational-explanation.js";
import { buildContext as tn03 } from "../__fixtures__/true-negative-03-plain-description.js";

function rule() {
  const r = getTypedRuleV2("G3");
  if (!r) throw new Error("G3 rule not registered");
  return r;
}

describe("G3 True Positives", () => {
  it("TP-01 prose 'returns JSON-RPC messages' + ai instructions fires critical", () => {
    const r = rule().analyze(tp01());
    expect(r.length).toBe(1);
    expect(r[0].rule_id).toBe("G3");
    expect(r[0].severity === "critical" || r[0].severity === "high").toBe(true);
    const factors = r[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("protocol_mimic_phrase_match");
  });

  it("TP-02 literal JSON-RPC envelope detected structurally (no regex)", () => {
    const r = rule().analyze(tp02());
    expect(r.length).toBe(1);
    const factors = r[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("literal_envelope_present");
  });

  it("TP-03 'returns MCP protocol' + tools/call + SSE multi-signal corroborates", () => {
    const r = rule().analyze(tp03());
    expect(r.length).toBe(1);
    const factors = r[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("multi_signal_corroboration");
  });
});

describe("G3 True Negatives", () => {
  it("TN-01 generic 'returns JSON' does not fire", () => {
    expect(rule().analyze(tn01()).length).toBe(0);
  });

  it("TN-02 educational/documentation content demoted by fence", () => {
    expect(rule().analyze(tn02()).length).toBe(0);
  });

  it("TN-03 plain descriptive prose does not fire", () => {
    expect(rule().analyze(tn03()).length).toBe(0);
  });
});

describe("G3 Evidence Chain Structure", () => {
  it("every finding has source + propagation + sink + impact", () => {
    const finding = rule().analyze(tp01())[0];
    const types = finding.chain.links.map((l) => l.type);
    expect(types).toContain("source");
    expect(types).toContain("propagation");
    expect(types).toContain("sink");
    expect(types).toContain("impact");
  });

  it("every non-impact link location is a structured tool Location", () => {
    const finding = rule().analyze(tp01())[0];
    for (const link of finding.chain.links) {
      if (link.type === "impact") continue;
      expect(isLocation(link.location)).toBe(true);
      if (isLocation(link.location)) {
        expect((link.location as Location).kind).toBe("tool");
      }
    }
  });

  it("sink carries CVE-2025-6514 precedent", () => {
    const finding = rule().analyze(tp02())[0];
    const sink = finding.chain.links.find((l) => l.type === "sink");
    expect(sink).toBeDefined();
    if (sink && sink.type === "sink") {
      expect(sink.cve_precedent).toBe("CVE-2025-6514");
    }
  });

  it("verification step targets are structured Locations", () => {
    const finding = rule().analyze(tp01())[0];
    for (const step of finding.chain.verification_steps ?? []) {
      expect(isLocation(step.target)).toBe(true);
    }
  });

  it("confidence capped at 0.85 (G3 charter)", () => {
    const finding = rule().analyze(tp02())[0];
    expect(finding.chain.confidence).toBeLessThanOrEqual(0.85);
  });

  it("threat reference cites CVE-2025-6514", () => {
    const finding = rule().analyze(tp01())[0];
    expect(finding.chain.threat_reference?.id).toBe("CVE-2025-6514");
  });
});

describe("G3 Rule Requirements", () => {
  it("declares tools: true and composite technique", () => {
    expect(rule().requires.tools).toBe(true);
    expect(rule().technique).toBe("composite");
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
