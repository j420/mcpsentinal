/**
 * C11 v2 — functional + evidence-integrity tests.
 *
 * Every CHARTER lethal edge case has at least one corresponding test
 * (nested quantifier, user-controlled, alternation overlap,
 * polynomial blow-up via inline mutation, safe negative).
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { RedosRule } from "../index.js";
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

const rule = new RedosRule();

function sourceContext(text: string): AnalysisContext {
  return {
    server: { id: "c11-t", name: "c11-test-server", description: null, github_url: null },
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

describe("C11 — fires (true positives)", () => {
  it("flags nested quantifier (a+)+", () => {
    const results = rule.analyze(loadFixture("true-positive-01-nested-quantifier.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C11");
    expect(results[0].severity).toBe("high");
  });

  it("flags `new RegExp(req.body.pattern)` (user-controlled)", () => {
    const results = rule.analyze(loadFixture("true-positive-02-user-controlled.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C11");
    expect(results[0].severity).toBe("high");
  });

  it("flags alternation overlap (a|ab)+", () => {
    const results = rule.analyze(loadFixture("true-positive-03-alternation-overlap.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C11");
    expect(results[0].severity).toBe("high");
  });
});

// ─── True negatives ──────────────────────────────────────────────────────

describe("C11 — does not fire (true negatives)", () => {
  it("does NOT fire on `/^[a-z0-9_-]+$/`", () => {
    const results = rule.analyze(loadFixture("true-negative-01-static-safe.ts"));
    expect(results.length).toBe(0);
  });

  it("does NOT fire when the file has no regex at all", () => {
    const results = rule.analyze(loadFixture("true-negative-02-no-regex.ts"));
    expect(results.length).toBe(0);
  });
});

// ─── Evidence integrity ──────────────────────────────────────────────────

describe("C11 — evidence integrity", () => {
  it("every link with a location field is a structured Location; every step.target too", () => {
    const results = rule.analyze(loadFixture("true-positive-01-nested-quantifier.ts"));
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      for (const link of r.chain.links) {
        if (link.type === "impact") continue;
        const loc = (link as { location?: unknown }).location;
        expect(isLocation(loc)).toBe(true);
      }
      for (const step of r.chain.verification_steps ?? []) {
        expect(isLocation(step.target)).toBe(true);
      }
    }
  });

  it("cites CWE-1333 on the threat reference", () => {
    const results = rule.analyze(loadFixture("true-positive-01-nested-quantifier.ts"));
    expect(results[0].chain.threat_reference?.id).toBe("CWE-1333");
  });

  it("every chain has source + sink + mitigation + impact", () => {
    const results = rule.analyze(loadFixture("true-positive-02-user-controlled.ts"));
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      const sources = getLinksOfType<SourceLink>(r.chain, "source");
      const sinks = getLinksOfType<SinkLink>(r.chain, "sink");
      const mits = getLinksOfType<MitigationLink>(r.chain, "mitigation");
      expect(sources.length).toBeGreaterThanOrEqual(1);
      expect(sinks.length).toBeGreaterThanOrEqual(1);
      expect(mits.length).toBeGreaterThanOrEqual(1);
    }
  });
});

// ─── Polynomial blow-up: explicit (.*)*  ────────────────────────────────

describe("C11 — polynomial blow-up via inline source", () => {
  it("flags explicit (.*)*  as polynomial-blowup", () => {
    const text = `
export function poly(input: string): boolean {
  const re = /^(.*)*$/;
  return re.test(input);
}
`;
    const results = rule.analyze(sourceContext(text));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C11");
  });
});

// ─── Confidence contract ─────────────────────────────────────────────────

describe("C11 — confidence contract", () => {
  it("caps confidence at 0.85 per charter", () => {
    const results = rule.analyze(loadFixture("true-positive-01-nested-quantifier.ts"));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.85);
      expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
    }
  });

  it("records ast_regex_pattern + regex_complexity_kind on every finding", () => {
    const results = rule.analyze(loadFixture("true-positive-02-user-controlled.ts"));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("ast_regex_pattern");
    expect(factors).toContain("regex_complexity_kind");
  });
});

// ─── Verification steps contract ─────────────────────────────────────────

describe("C11 — verification steps", () => {
  it("emits at least three steps on every finding", () => {
    const results = rule.analyze(loadFixture("true-positive-01-nested-quantifier.ts"));
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      const steps = r.chain.verification_steps as VerificationStep[];
      expect(steps.length).toBeGreaterThanOrEqual(3);
      for (const s of steps) {
        expect(isLocation(s.target)).toBe(true);
        expect(s.instruction.length).toBeGreaterThan(20);
      }
    }
  });
});
