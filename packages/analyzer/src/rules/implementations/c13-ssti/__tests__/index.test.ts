/**
 * C13 v2 — functional + evidence-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { SsTiRule } from "../index.js";
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

const rule = new SsTiRule();

function sourceContext(text: string): AnalysisContext {
  return {
    server: { id: "c13-t", name: "c13-test-server", description: null, github_url: null },
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

describe("C13 — fires (true positives)", () => {
  it("flags Handlebars.compile on a user-controlled template", () => {
    const results = rule.analyze(loadFixture("true-positive-01-handlebars-compile.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C13");
  });

  it("flags ejs.render with user-controlled template source", () => {
    const results = rule.analyze(loadFixture("true-positive-02-ejs-render.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C13");
  });

  it("flags nunjucks.renderString with user-controlled input", () => {
    const results = rule.analyze(loadFixture("true-positive-03-nunjucks-renderstring.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C13");
  });
});

// ─── True negatives ───────────────────────────────────────────────────────

describe("C13 — does not fire (true negatives)", () => {
  it("does NOT flag a static template literal", () => {
    const results = rule.analyze(loadFixture("true-negative-01-static-template.ts"));
    const critical = results.filter((r) => r.severity === "critical");
    expect(critical.length).toBe(0);
  });

  it("does NOT flag express-style res.render with a filename", () => {
    const results = rule.analyze(loadFixture("true-negative-02-express-render-filename.ts"));
    const critical = results.filter((r) => r.severity === "critical");
    expect(critical.length).toBe(0);
  });
});

// ─── Evidence integrity ───────────────────────────────────────────────────

describe("C13 — evidence integrity", () => {
  it("every link with a location is a structured Location; every VerificationStep.target is a Location", () => {
    const results = rule.analyze(loadFixture("true-positive-01-handlebars-compile.ts"));
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

  it("every chain has a source + template-render sink", () => {
    const results = rule.analyze(loadFixture("true-positive-02-ejs-render.ts"));
    expect(results.length).toBeGreaterThan(0);
    const sources = getLinksOfType<SourceLink>(results[0].chain, "source");
    const sinks = getLinksOfType<SinkLink>(results[0].chain, "sink");
    expect(sources.length).toBeGreaterThanOrEqual(1);
    expect(sinks.length).toBeGreaterThanOrEqual(1);
    expect(sinks[0].sink_type).toBe("template-render");
  });

  it("every chain records a mitigation link", () => {
    const results = rule.analyze(loadFixture("true-positive-03-nunjucks-renderstring.ts"));
    expect(results.length).toBeGreaterThan(0);
    const mitigations = getLinksOfType<MitigationLink>(results[0].chain, "mitigation");
    expect(mitigations.length).toBeGreaterThanOrEqual(1);
  });

  it("cites CWE-1336 on the threat reference", () => {
    const results = rule.analyze(loadFixture("true-positive-01-handlebars-compile.ts"));
    expect(results[0].chain.threat_reference?.id).toBe("CWE-1336");
  });
});

// ─── Confidence ──────────────────────────────────────────────────────────

describe("C13 — confidence", () => {
  it("caps confidence at 0.92 per charter", () => {
    const results = rule.analyze(loadFixture("true-positive-01-handlebars-compile.ts"));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.92);
      expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
    }
  });

  it("records ast_confirmed + interprocedural_hops factors", () => {
    const results = rule.analyze(loadFixture("true-positive-01-handlebars-compile.ts"));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    const hasEvidenceOrigin =
      factors.includes("ast_confirmed") || factors.includes("lightweight_taint_fallback");
    expect(hasEvidenceOrigin).toBe(true);
    expect(factors).toContain("interprocedural_hops");
  });
});

// ─── Mutation ────────────────────────────────────────────────────────────

describe("C13 — mutation (switching compile source to literal removes the finding)", () => {
  it("critical finding disappears when compile source is a static literal", () => {
    const vulnerable = `
import Handlebars from "handlebars";
export function render(req) {
  const tpl = req.body.template;
  return Handlebars.compile(tpl)({});
}
`;
    const safe = `
import Handlebars from "handlebars";
const STATIC = "Hello {{ name }}!";
const compiled = Handlebars.compile(STATIC);
export function render(req) {
  return compiled({ name: req.body.name });
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

describe("C13 — verification steps", () => {
  it("every unsanitised finding emits at least three verification steps", () => {
    const results = rule.analyze(loadFixture("true-positive-01-handlebars-compile.ts")).filter(
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
