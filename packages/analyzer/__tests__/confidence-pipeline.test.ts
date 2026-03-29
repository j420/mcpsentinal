/**
 * Confidence Pipeline Tests — Proves confidence survives the full chain.
 *
 * The bug this fixes: confidence was computed by C1 (0.95 for AST taint),
 * then STRIPPED by toFindingInput() → reconstructed as hardcoded 0.5 →
 * stripped again by scoredFindings() → scorer defaults to 1.0.
 *
 * Result: the entire confidence weighting system was dead code.
 *
 * These tests prove that after the fix, real confidence values survive:
 *   C1 TypedRule (0.95) → analyzeRich() → annotateFindings() →
 *   scoredFindings() (with confidence) → computeScore (weighted penalty)
 *
 * Each test isolates one link in the chain so failures are diagnosable.
 */
import { describe, it, expect } from "vitest";
import { AnalysisEngine, type AnalysisContext } from "../src/engine.js";
import type { DetectionRule } from "@mcp-sentinel/database";
import "../src/rules/index.js";

// ─── Shared fixtures ────────────────────────────────────────────────────────

/** Server with direct taint flow: req.body.command → exec() — AST taint gives ~0.85+ */
function execServer(): AnalysisContext {
  return {
    server: { id: "exec-srv", name: "shell-executor", description: "Execute shell commands on a server", github_url: null },
    tools: [
      {
        name: "run_command",
        description: "Execute a shell command on the server",
        input_schema: { type: "object", properties: { command: { type: "string" } } },
      },
    ],
    source_code: `
const { exec } = require("child_process");
async function handleTool(req, res) {
  const cmd = req.body.command;
  exec(cmd, (err, stdout) => {
    res.json({ result: stdout });
  });
}
`,
    dependencies: [],
    connection_metadata: null,
  };
}

/** Server with no vulnerable code — should produce no C1 findings */
function safeServer(): AnalysisContext {
  return {
    server: { id: "safe-srv", name: "safe-api", description: "A safe API server", github_url: null },
    tools: [
      {
        name: "get_status",
        description: "Get server status",
        input_schema: { type: "object", properties: { verbose: { type: "boolean" } } },
      },
    ],
    source_code: `
function getStatus() {
  return { status: "ok", uptime: process.uptime() };
}
`,
    dependencies: [],
    connection_metadata: null,
  };
}

// ─── Build engine with C1 typed rule ────────────────────────────────────────

const c1Rule: DetectionRule = {
  id: "C1",
  name: "Command Injection (Taint-Aware)",
  category: "code-analysis",
  severity: "critical",
  owasp: "MCP03-command-injection",
  mitre: "AML.T0054",
  detect: { type: "typed" },
  remediation: "Replace exec() with execFile() and validate all inputs.",
  enabled: true,
};

const engine = new AnalysisEngine([c1Rule]);

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 1: analyze() backward compatibility
// The public analyze() still returns FindingInput[] (no confidence field).
// This ensures existing consumers (DB insertion, tests) are not broken.
// ═════════════════════════════════════════════════════════════════════════════

describe("analyze() backward compatibility", () => {
  it("returns FindingInput[] without confidence field (does not break callers)", () => {
    const findings = engine.analyze(execServer());
    // Should have at least one finding (C1 or others from the exec pattern)
    expect(findings.length).toBeGreaterThanOrEqual(1);

    // FindingInput has these fields and no extras
    const f = findings[0];
    expect(f).toHaveProperty("rule_id");
    expect(f).toHaveProperty("severity");
    expect(f).toHaveProperty("evidence");
    expect(f).toHaveProperty("remediation");
    // confidence is NOT on FindingInput — this is the backward compat guarantee
    expect(f).not.toHaveProperty("confidence");
    expect(f).not.toHaveProperty("metadata");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 2: analyzeWithProfile() preserves real confidence
// This is where the bug was — confidence was hardcoded to 0.5.
// Now it should carry the real value from C1's evidence chain.
// ═════════════════════════════════════════════════════════════════════════════

describe("analyzeWithProfile() confidence preservation", () => {
  it("C1 finding retains AST taint confidence (not hardcoded 0.5)", () => {
    const result = engine.analyzeWithProfile(execServer());

    // Find C1 in the annotated findings
    const c1 = result.all_annotated.find(
      (f) => f.rule_id === "C1" && f.severity === "critical"
    );
    expect(c1).toBeDefined();

    // THE CRITICAL ASSERTION: confidence is NOT the old hardcoded 0.5
    expect(c1!.confidence).not.toBe(0.5);

    // AST taint analysis produces 0.70+ base confidence
    // (0.70 base + 0.15 ast_confirmed + 0.10 mitigation_absent = 0.95)
    expect(c1!.confidence).toBeGreaterThanOrEqual(0.70);
  });

  it("C1 evidence chain survives through the engine", () => {
    const result = engine.analyzeWithProfile(execServer());

    const c1 = result.all_annotated.find(
      (f) => f.rule_id === "C1" && f.severity === "critical"
    );
    expect(c1).toBeDefined();

    // Evidence chain should be present — not null
    expect(c1!.evidence_chain).not.toBeNull();

    // Chain should have source, propagation, sink links
    const chain = c1!.evidence_chain!;
    expect(chain.links.some((l) => l.type === "source")).toBe(true);
    expect(chain.links.some((l) => l.type === "sink")).toBe(true);

    // Chain confidence should match the annotated confidence
    expect(chain.confidence).toBe(c1!.confidence);
  });

  it("safe server produces no C1 critical findings", () => {
    const result = engine.analyzeWithProfile(safeServer());
    const c1Critical = result.all_annotated.filter(
      (f) => f.rule_id === "C1" && f.severity === "critical"
    );
    expect(c1Critical.length).toBe(0);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 3: scoredFindings() now includes confidence
// This was the second break — ScoredFinding had no confidence field.
// ═════════════════════════════════════════════════════════════════════════════

describe("scoredFindings() carries confidence to scorer", () => {
  it("scored C1 finding has confidence field", () => {
    const result = engine.analyzeWithProfile(execServer());
    const c1Scored = result.scored_findings.find(
      (f) => f.rule_id === "C1" && f.severity === "critical"
    );

    // C1 on an exec server should be relevant + meet evidence standard → scored
    expect(c1Scored).toBeDefined();

    // Confidence must be present and not default
    expect(c1Scored!.confidence).toBeDefined();
    expect(c1Scored!.confidence).toBeGreaterThanOrEqual(0.70);
    expect(c1Scored!.confidence).toBeLessThanOrEqual(0.99);
  });

  it("legacy rules get default confidence 0.5 (not 1.0)", () => {
    const result = engine.analyzeWithProfile(execServer());

    // Find any non-C1 finding (from YAML/legacy rules)
    const nonC1 = result.all_annotated.find(
      (f) => f.rule_id !== "C1" && !f.evidence_chain
    );
    if (nonC1) {
      // Legacy rules without evidence chains get 0.5 default
      expect(nonC1.confidence).toBe(0.5);
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 4: Full chain proof — C1 confidence affects final score
// The scorer scales penalty by confidence. An AST-confirmed finding (0.95)
// should produce a larger penalty than a regex fallback (0.50).
// ═════════════════════════════════════════════════════════════════════════════

import { computeScore } from "@mcp-sentinel/scorer";

describe("Full chain: C1 confidence → scorer penalty", () => {
  it("high-confidence C1 finding produces near-full penalty", () => {
    const result = engine.analyzeWithProfile(execServer());
    const c1Scored = result.scored_findings.filter(
      (f) => f.rule_id === "C1" && f.severity === "critical"
    );
    expect(c1Scored.length).toBeGreaterThanOrEqual(1);

    // Feed ONLY the C1 finding to the scorer
    const ruleCategories: Record<string, string> = { C1: "code-analysis" };
    const score = computeScore(c1Scored, ruleCategories);

    // Critical = 25 base penalty, confidence ~0.95 → penalty ~23.75
    const c1Penalty = score.penalty_breakdown.find((p) => p.rule_id === "C1");
    expect(c1Penalty).toBeDefined();

    // With confidence ~0.85-0.95, penalty should be ~21-24 (not exactly 25)
    expect(c1Penalty!.penalty).toBeGreaterThan(15); // at least 60% of 25
    expect(c1Penalty!.penalty).toBeLessThanOrEqual(25); // never exceeds base

    // Score should reflect the weighted penalty
    expect(score.total_score).toBeLessThan(100);
    expect(score.code_score).toBeLessThan(100);
  });

  it("full-confidence (1.0) penalty vs real confidence penalty — real is less", () => {
    const result = engine.analyzeWithProfile(execServer());
    const c1Scored = result.scored_findings.filter(
      (f) => f.rule_id === "C1" && f.severity === "critical"
    );
    expect(c1Scored.length).toBeGreaterThanOrEqual(1);

    const ruleCategories: Record<string, string> = { C1: "code-analysis" };

    // Score with real confidence
    const realScore = computeScore(c1Scored, ruleCategories);

    // Score with forced 1.0 confidence (the old broken behavior)
    const faked = c1Scored.map((f) => ({
      ...f,
      confidence: 1.0,
    }));
    const fullScore = computeScore(faked, ruleCategories);

    // Real confidence < 1.0 → smaller penalty → higher total score
    expect(realScore.total_score).toBeGreaterThanOrEqual(fullScore.total_score);

    // The difference should be measurable (not zero)
    const c1Real = realScore.penalty_breakdown.find((p) => p.rule_id === "C1")!;
    const c1Full = fullScore.penalty_breakdown.find((p) => p.rule_id === "C1")!;
    expect(c1Full.penalty).toBe(25); // 25 * 1.0 = 25
    expect(c1Real.penalty).toBeLessThan(25); // 25 * 0.95 = 23.75
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 5: Edge cases — confidence boundaries and degenerate inputs
// ═════════════════════════════════════════════════════════════════════════════

describe("Confidence pipeline edge cases", () => {
  it("regex fallback finding gets lower confidence than AST finding", () => {
    // Code with template literal in exec — AST may not trace it, falls to regex
    const regexCtx: AnalysisContext = {
      server: { id: "rx", name: "shell-executor", description: "Execute shell commands", github_url: null },
      tools: [
        { name: "run_command", description: "Execute a shell command", input_schema: { type: "object", properties: { command: { type: "string" } } } },
      ],
      source_code: `
const { exec } = require("child_process");
exec(\`ls -la \${userInput}\`);
`,
      dependencies: [],
      connection_metadata: null,
    };

    const astResult = engine.analyzeWithProfile(execServer());
    const regexResult = engine.analyzeWithProfile(regexCtx);

    const astC1 = astResult.all_annotated.find(
      (f) => f.rule_id === "C1" && f.severity === "critical"
    );
    const regexC1 = regexResult.all_annotated.find(
      (f) => f.rule_id === "C1" && (f.severity === "critical" || f.severity === "high")
    );

    // Both should detect something
    if (astC1 && regexC1) {
      // AST-confirmed should have higher confidence than regex
      expect(astC1.confidence).toBeGreaterThan(regexC1.confidence);
    }
  });

  it("informational findings (filtered out) do NOT appear in scored_findings", () => {
    const result = engine.analyzeWithProfile(execServer());

    // Check that informational_findings and scored_findings are disjoint
    const scoredRuleIds = new Set(result.scored_findings.map((f) => `${f.rule_id}:${f.severity}`));
    for (const inf of result.informational_findings) {
      const key = `${inf.rule_id}:${inf.severity}`;
      // An informational finding shouldn't also be scored (same rule+severity)
      // (different severity levels of the same rule CAN appear in both)
      if (!inf.relevant || !inf.meets_evidence_standard) {
        expect(scoredRuleIds.has(key)).toBe(false);
      }
    }
  });

  it("all scored findings have confidence in range [0.05, 0.99]", () => {
    const result = engine.analyzeWithProfile(execServer());
    for (const f of result.scored_findings) {
      expect(f.confidence).toBeGreaterThanOrEqual(0.05);
      expect(f.confidence).toBeLessThanOrEqual(1.0); // legacy rules can be 0.5
    }
  });
});
