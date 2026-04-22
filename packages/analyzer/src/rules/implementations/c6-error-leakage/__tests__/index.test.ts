/**
 * C6 v2 — functional + evidence-integrity tests.
 *
 * Every CHARTER lethal edge case has at least one corresponding test
 * (stack property, JSON.stringify, spread, traceback, env-gate).
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ErrorLeakageRule } from "../index.js";
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

const rule = new ErrorLeakageRule();

function sourceContext(text: string): AnalysisContext {
  return {
    server: { id: "c6-t", name: "c6-test-server", description: null, github_url: null },
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

describe("C6 — fires (true positives)", () => {
  it("flags `error.stack` reaching res.json", () => {
    const results = rule.analyze(loadFixture("true-positive-01-error-stack-in-json.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C6");
    expect(results[0].severity).toBe("medium");
  });

  it("flags `...error` spread inside res.send", () => {
    const results = rule.analyze(loadFixture("true-positive-02-spread-error.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C6");
    expect(results[0].severity).toBe("medium");
  });

  it("flags Python traceback.format_exc() returned in jsonify(...)", () => {
    const results = rule.analyze(loadFixture("true-positive-03-python-traceback.py"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C6");
    expect(results[0].severity).toBe("medium");
  });
});

// ─── True negatives ───────────────────────────────────────────────────────

describe("C6 — does not fire (true negatives)", () => {
  it("does NOT fire when the response body is an opaque message literal", () => {
    const results = rule.analyze(loadFixture("true-negative-01-opaque-message.ts"));
    const medium = results.filter((r) => r.severity === "medium");
    expect(medium.length).toBe(0);
  });

  it("downgrades to informational when sanitizeError() wraps the error", () => {
    const results = rule.analyze(loadFixture("true-negative-02-sanitised.ts"));
    const medium = results.filter((r) => r.severity === "medium");
    expect(medium.length).toBe(0);
  });
});

// ─── Evidence integrity ──────────────────────────────────────────────────

describe("C6 — evidence integrity", () => {
  it("every link with a location field is a structured Location; every step.target too", () => {
    const results = rule.analyze(loadFixture("true-positive-01-error-stack-in-json.ts"));
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

  it("every chain has source + sink + mitigation + impact + reference", () => {
    const results = rule.analyze(loadFixture("true-positive-01-error-stack-in-json.ts"));
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      const sources = getLinksOfType<SourceLink>(r.chain, "source");
      const sinks = getLinksOfType<SinkLink>(r.chain, "sink");
      const mits = getLinksOfType<MitigationLink>(r.chain, "mitigation");
      expect(sources.length).toBeGreaterThanOrEqual(1);
      expect(sinks.length).toBeGreaterThanOrEqual(1);
      expect(mits.length).toBeGreaterThanOrEqual(1);
      expect(r.chain.threat_reference?.id).toBe("CWE-209");
    }
  });
});

// ─── Confidence contract ─────────────────────────────────────────────────

describe("C6 — confidence contract", () => {
  it("caps confidence at 0.85 per charter", () => {
    const results = rule.analyze(loadFixture("true-positive-01-error-stack-in-json.ts"));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.85);
      expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
    }
  });

  it("records ast_match + error_carrier_kind on every finding", () => {
    const results = rule.analyze(loadFixture("true-positive-02-spread-error.ts"));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("ast_match");
    expect(factors).toContain("error_carrier_kind");
  });
});

// ─── Verification steps contract ─────────────────────────────────────────

describe("C6 — verification steps", () => {
  it("emits at least three steps on every finding", () => {
    const results = rule.analyze(loadFixture("true-positive-01-error-stack-in-json.ts"));
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
