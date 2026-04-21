/**
 * A9 — Encoded Instructions (Rule Standard v2) — rule-local test suite.
 *
 * Covers:
 *   1. True positives: base64, URL-encoded, hex-escape, mixed — each via a
 *      dedicated __fixtures__/ builder.
 *   2. True negatives: plain description, legitimate short binary ref, JWT
 *      structural-docs reference.
 *   3. Evidence chain structure: source + propagation + sink + mitigation +
 *      impact + verification steps + threat reference + confidence cap.
 *   4. Severity escalation: mixed-encoding → critical.
 */

import { describe, it, expect } from "vitest";
import "../index.js"; // side-effect: registerTypedRuleV2
import { getTypedRuleV2 } from "../../../base.js";

import { buildContext as tp01 } from "../__fixtures__/true-positive-01-base64-payload.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-url-encoded-instruction.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-hex-escape-payload.js";
import { buildContext as tp04 } from "../__fixtures__/true-positive-04-mixed-encoding.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-plain-description.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-legitimate-binary-reference.js";
import { buildContext as tn03 } from "../__fixtures__/true-negative-03-jwt-in-docs.js";

function rule() {
  const r = getTypedRuleV2("A9");
  if (!r) throw new Error("A9 rule not registered");
  return r;
}

// ─── True Positives ──────────────────────────────────────────────────────────

describe("A9 True Positives", () => {
  it("TP-01: detects base64 payload in tool description", () => {
    const results = rule().analyze(tp01());
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("A9");
    // Payload decodes to an injection sentence → keyword_hits should boost confidence
    expect(results[0].chain.confidence).toBeGreaterThanOrEqual(0.5);
  });

  it("TP-02: detects URL-encoded run in parameter description", () => {
    const results = rule().analyze(tp02());
    expect(results.some((f) => f.rule_id === "A9")).toBe(true);
    const finding = results.find((f) => f.rule_id === "A9")!;
    // Source location must reference the parameter path
    const sourceLink = finding.chain.links.find((l) => l.type === "source");
    expect(sourceLink?.location).toContain("param:query");
  });

  it("TP-03: detects \\xNN hex escapes in initialize instructions field", () => {
    const results = rule().analyze(tp03());
    expect(results.some((f) => f.rule_id === "A9")).toBe(true);
    const finding = results.find((f) => f.rule_id === "A9")!;
    // Must be sourced from the initialize surface
    const sourceLink = finding.chain.links.find((l) => l.type === "source") as
      | { source_type?: string; location: string }
      | undefined;
    expect(sourceLink?.source_type).toBe("initialize-field");
    expect(sourceLink?.location).toContain("initialize:instructions");
    // Decoded payload hits the "system:" LLM role prefix → critical factor
    const factors = finding.chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("llm_control_token_after_decode");
  });

  it("TP-04: mixed-encoding escalates severity to critical", () => {
    const results = rule().analyze(tp04());
    expect(results.length).toBeGreaterThan(0);
    const finding = results.find((f) => f.rule_id === "A9")!;
    expect(finding.severity).toBe("critical");
    // Chain must carry the mixed_encoding_layering factor
    const factorNames = finding.chain.confidence_factors.map((f) => f.factor);
    expect(factorNames).toContain("mixed_encoding_layering");
  });
});

// ─── True Negatives ──────────────────────────────────────────────────────────

describe("A9 True Negatives", () => {
  it("TN-01: does NOT fire on plain English description", () => {
    const results = rule().analyze(tn01());
    expect(results.filter((f) => f.rule_id === "A9").length).toBe(0);
  });

  it("TN-02: does NOT fire on short legitimate base64 example", () => {
    const results = rule().analyze(tn02());
    expect(results.filter((f) => f.rule_id === "A9").length).toBe(0);
  });

  it("TN-03: does NOT fire on JWT structural documentation", () => {
    const results = rule().analyze(tn03());
    expect(results.filter((f) => f.rule_id === "A9").length).toBe(0);
  });
});

// ─── Evidence Chain Structure ────────────────────────────────────────────────

describe("A9 Evidence Chain Structure", () => {
  it("every finding has source + propagation + sink + mitigation + impact links", () => {
    const results = rule().analyze(tp01());
    const finding = results.find((f) => f.rule_id === "A9")!;
    const types = finding.chain.links.map((l) => l.type);
    expect(types).toContain("source");
    expect(types).toContain("propagation");
    expect(types).toContain("sink");
    expect(types).toContain("mitigation");
    expect(types).toContain("impact");
  });

  it("evidence chain has ≥4 verification steps, each with a structured target", () => {
    const results = rule().analyze(tp01());
    const finding = results.find((f) => f.rule_id === "A9")!;
    const steps = finding.chain.verification_steps!;
    expect(steps.length).toBeGreaterThanOrEqual(4);
    for (const s of steps) {
      // Target must be non-empty and reference the rule's location format
      expect(s.target).toBeTruthy();
      expect(s.target.length).toBeGreaterThan(0);
      expect(s.step_type).toBeDefined();
      expect(s.instruction.length).toBeGreaterThan(20);
      expect(s.expected_observation.length).toBeGreaterThan(10);
    }
  });

  it("threat reference cites MITRE AML.T0054", () => {
    const results = rule().analyze(tp01());
    const finding = results.find((f) => f.rule_id === "A9")!;
    expect(finding.chain.threat_reference?.id).toBe("AML.T0054");
  });

  it("confidence is capped at 0.90", () => {
    const results = rule().analyze(tp04());
    const finding = results.find((f) => f.rule_id === "A9")!;
    expect(finding.chain.confidence).toBeLessThanOrEqual(0.9);
  });

  it("confidence factors include structural_encoding_run anchor", () => {
    const results = rule().analyze(tp01());
    const finding = results.find((f) => f.rule_id === "A9")!;
    const factors = finding.chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("structural_encoding_run");
  });
});

// ─── Rule Requirements ───────────────────────────────────────────────────────

describe("A9 Rule Requirements", () => {
  it("declares tools: true", () => {
    expect(rule().requires.tools).toBe(true);
  });

  it("declares technique: composite", () => {
    expect(rule().technique).toBe("composite");
  });

  it("returns [] when context has no tools", () => {
    const results = rule().analyze({
      server: { id: "empty", name: "e", description: null, github_url: null },
      tools: [],
      source_code: null,
      dependencies: [],
      connection_metadata: null,
    });
    expect(results.length).toBe(0);
  });
});
