/**
 * Dynamic Confidence — C1 Command Injection (Regression)
 *
 * C1 uses AST-based taint analysis (analyzeASTTaint) which produces
 * flow.confidence — a value from the taint engine, NOT from EvidenceChainBuilder.
 *
 * Phase 1's chain.confidence wiring must NOT break C1:
 *   - c1-command-injection.ts line 115: `confidence: flow.confidence`
 *   - The finding also builds an evidence chain via buildASTEvidenceChain(),
 *     but the finding.confidence is set from the taint flow, not the chain.
 *
 * This test verifies C1 still produces dynamic confidence values from taint
 * analysis, not old hardcoded values like 0.85 or 0.90.
 */
import { describe, it, expect } from "vitest";
import type { AnalysisContext } from "../src/engine.js";
import { getTypedRule } from "../src/rules/base.js";
import "../src/rules/index.js";

function ctx(src: string): AnalysisContext {
  return { server: { id: "t", name: "test", description: null, github_url: null }, tools: [], source_code: src, dependencies: [], connection_metadata: null };
}

describe("C1 — AST taint confidence regression", () => {
  it("req.body.command → exec() produces critical finding with taint-derived confidence", () => {
    const findings = getTypedRule("C1")!.analyze(ctx(
      `const { exec } = require("child_process");\n` +
      `app.post("/run", (req, res) => { exec(req.body.command); });`
    ));

    const c1Critical = findings.filter(f => f.rule_id === "C1" && f.severity === "critical");
    expect(c1Critical.length).toBeGreaterThanOrEqual(1);

    const conf = c1Critical[0].confidence;

    // Taint-derived confidence must be in valid range.
    // AST taint produces values based on flow analysis: direct flows get ~0.85-0.95,
    // multi-hop flows get lower values. Regex fallback gets 0.60-0.80.
    expect(conf).toBeGreaterThanOrEqual(0.30);
    expect(conf).toBeLessThanOrEqual(0.99);
  });

  it("C1 confidence is NOT an old hardcoded value (0.85 or 0.90)", () => {
    const findings = getTypedRule("C1")!.analyze(ctx(
      `const { exec } = require("child_process");\n` +
      `app.post("/run", (req, res) => { exec(req.body.command); });`
    ));

    const c1Critical = findings.filter(f => f.rule_id === "C1" && f.severity === "critical");
    expect(c1Critical.length).toBeGreaterThanOrEqual(1);

    // Before Phase 1, C1 already used flow.confidence from taint analysis,
    // so it was already dynamic. But some regex fallback paths used hardcoded
    // 0.85 or 0.90. For this direct taint flow (req.body → exec), the value
    // should come from AST analysis, not a bare constant.
    // We assert it's not EXACTLY those old constants (within floating point).
    const conf = c1Critical[0].confidence;
    expect(conf).not.toBeCloseTo(0.85, 10);
    expect(conf).not.toBeCloseTo(0.90, 10);
  });
});
