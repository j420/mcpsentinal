/**
 * C16 v2 — functional + evidence-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DynamicCodeEvalRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";
import type {
  EvidenceChain,
  SourceLink,
  SinkLink,
  MitigationLink,
  VerificationStep,
} from "../../../../evidence.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "__fixtures__");

const rule = new DynamicCodeEvalRule();

function sourceContext(text: string): AnalysisContext {
  return {
    server: { id: "c16-t", name: "c16-test-server", description: null, github_url: null },
    tools: [],
    source_code: text,
    dependencies: [],
    connection_metadata: null,
  };
}

function loadFixture(name: string): AnalysisContext {
  return sourceContext(readFileSync(join(FIX, name), "utf8"));
}

function getLinksOfType<T extends { type: string }>(chain: EvidenceChain, type: string): T[] {
  return chain.links.filter((l) => l.type === type) as T[];
}

// ─── True positives ───────────────────────────────────────────────────────

describe("C16 — fires (true positives)", () => {
  it("flags eval() with direct user input", () => {
    const results = rule.analyze(loadFixture("true-positive-01-eval.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C16");
  });

  it("flags new Function() with user code", () => {
    const results = rule.analyze(loadFixture("true-positive-02-new-function.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C16");
  });

  it("flags vm.runInNewContext with user code", () => {
    const results = rule.analyze(loadFixture("true-positive-03-vm-runincontext.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C16");
  });
});

// ─── True negatives ───────────────────────────────────────────────────────

describe("C16 — does not fire (true negatives)", () => {
  it("does NOT emit a critical finding for JSON.parse", () => {
    const results = rule.analyze(loadFixture("true-negative-01-json-parse.ts"));
    const critical = results.filter((r) => r.severity === "critical");
    expect(critical.length).toBe(0);
  });

  it("does NOT fire on eval with a hardcoded string literal", () => {
    const results = rule.analyze(loadFixture("true-negative-02-eval-literal.ts"));
    expect(results.length).toBe(0);
  });
});

// ─── Evidence integrity ───────────────────────────────────────────────────

describe("C16 — evidence integrity", () => {
  it("every link with a location is a structured Location; every VerificationStep.target is a Location", () => {
    const results = rule.analyze(loadFixture("true-positive-01-eval.ts"));
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      for (const link of r.chain.links) {
        if (link.type === "impact") continue;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        expect(isLocation((link as any).location)).toBe(true);
      }
      for (const step of r.chain.verification_steps ?? []) {
        expect(isLocation(step.target)).toBe(true);
      }
    }
  });

  it("every chain has a source + code-evaluation sink link", () => {
    const results = rule.analyze(loadFixture("true-positive-02-new-function.ts"));
    expect(results.length).toBeGreaterThan(0);
    const sources = getLinksOfType<SourceLink>(results[0].chain, "source");
    const sinks = getLinksOfType<SinkLink>(results[0].chain, "sink");
    expect(sources.length).toBeGreaterThanOrEqual(1);
    expect(sinks.length).toBeGreaterThanOrEqual(1);
    expect(sinks[0].sink_type).toBe("code-evaluation");
  });

  it("every chain records a mitigation link", () => {
    const results = rule.analyze(loadFixture("true-positive-01-eval.ts"));
    expect(results.length).toBeGreaterThan(0);
    const mitigations = getLinksOfType<MitigationLink>(results[0].chain, "mitigation");
    expect(mitigations.length).toBeGreaterThanOrEqual(1);
  });

  it("cites CWE-95 on the threat reference", () => {
    const results = rule.analyze(loadFixture("true-positive-01-eval.ts"));
    expect(results[0].chain.threat_reference?.id).toBe("CWE-95");
  });
});

// ─── Confidence ──────────────────────────────────────────────────────────

describe("C16 — confidence", () => {
  it("caps confidence at 0.92 per charter", () => {
    const results = rule.analyze(loadFixture("true-positive-01-eval.ts"));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.92);
      expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
    }
  });

  it("records ast_confirmed + interprocedural_hops factors", () => {
    const results = rule.analyze(loadFixture("true-positive-01-eval.ts"));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    const hasEvidenceOrigin =
      factors.includes("ast_confirmed") || factors.includes("lightweight_taint_fallback");
    expect(hasEvidenceOrigin).toBe(true);
    expect(factors).toContain("interprocedural_hops");
  });
});

// ─── Mutation ────────────────────────────────────────────────────────────

describe("C16 — mutation (swap eval for JSON.parse removes the finding)", () => {
  it("critical finding disappears when eval is replaced by JSON.parse", () => {
    const vulnerable = `
export function f(req) {
  const expr = req.body.expr;
  return eval(expr);
}
`;
    const safe = `
export function f(req) {
  const expr = req.body.expr;
  return JSON.parse(expr);
}
`;
    const vulnerableCritical = rule
      .analyze(sourceContext(vulnerable))
      .filter((r) => r.severity === "critical");
    const safeCritical = rule
      .analyze(sourceContext(safe))
      .filter((r) => r.severity === "critical");
    expect(vulnerableCritical.length).toBeGreaterThan(0);
    expect(safeCritical.length).toBe(0);
  });
});

// ─── Verification steps ──────────────────────────────────────────────────

describe("C16 — verification steps", () => {
  it("every unsanitised finding emits at least three verification steps", () => {
    const results = rule.analyze(loadFixture("true-positive-01-eval.ts")).filter(
      (r) => r.severity === "critical",
    );
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      const steps = r.chain.verification_steps as VerificationStep[];
      expect(steps.length).toBeGreaterThanOrEqual(3);
      for (const s of steps) {
        expect(isLocation(s.target)).toBe(true);
      }
    }
  });
});
