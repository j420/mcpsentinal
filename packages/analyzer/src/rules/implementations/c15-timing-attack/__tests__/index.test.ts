/**
 * C15 v2 — functional + evidence-integrity tests.
 *
 * Every CHARTER lethal edge case has at least one corresponding test.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { TimingAttackRule } from "../index.js";
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

const rule = new TimingAttackRule();

function sourceContext(text: string): AnalysisContext {
  return {
    server: { id: "c15-t", name: "c15-test-server", description: null, github_url: null },
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

describe("C15 — fires (true positives)", () => {
  it("flags `apiKey === req.headers.authorization`", () => {
    const results = rule.analyze(loadFixture("true-positive-01-strict-equals.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C15");
    expect(results[0].severity).toBe("high");
  });

  it("flags `sessionToken.startsWith(req.body.incomingToken)`", () => {
    const results = rule.analyze(loadFixture("true-positive-02-startswith.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C15");
    expect(results[0].severity).toBe("high");
  });

  it("flags Python `API_KEY == provided_token`", () => {
    const results = rule.analyze(loadFixture("true-positive-03-python-equality.py"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C15");
    expect(results[0].severity).toBe("high");
  });
});

// ─── True negatives ──────────────────────────────────────────────────────

describe("C15 — does not fire (true negatives)", () => {
  it("does NOT fire when crypto.timingSafeEqual is the comparison", () => {
    const results = rule.analyze(loadFixture("true-negative-01-timing-safe.ts"));
    expect(results.length).toBe(0);
  });

  it("does NOT fire when neither operand is a secret-named identifier", () => {
    const results = rule.analyze(loadFixture("true-negative-02-no-secret.ts"));
    expect(results.length).toBe(0);
  });
});

// ─── Evidence integrity ──────────────────────────────────────────────────

describe("C15 — evidence integrity", () => {
  it("every link with a location field is a structured Location; every step.target too", () => {
    const results = rule.analyze(loadFixture("true-positive-01-strict-equals.ts"));
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

  it("cites CWE-208 on the threat reference", () => {
    const results = rule.analyze(loadFixture("true-positive-01-strict-equals.ts"));
    expect(results[0].chain.threat_reference?.id).toBe("CWE-208");
  });

  it("every chain has source + sink + mitigation + impact", () => {
    const results = rule.analyze(loadFixture("true-positive-02-startswith.ts"));
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

// ─── Confidence contract ─────────────────────────────────────────────────

describe("C15 — confidence contract", () => {
  it("caps confidence at 0.90 per charter", () => {
    const results = rule.analyze(loadFixture("true-positive-01-strict-equals.ts"));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.9);
      expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
    }
  });

  it("records ast_comparison_shape + secret_identifier_match on every finding", () => {
    const results = rule.analyze(loadFixture("true-positive-03-python-equality.py"));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("ast_comparison_shape");
    expect(factors).toContain("secret_identifier_match");
  });
});

// ─── Verification steps contract ─────────────────────────────────────────

describe("C15 — verification steps", () => {
  it("emits at least three steps on every finding", () => {
    const results = rule.analyze(loadFixture("true-positive-01-strict-equals.ts"));
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
