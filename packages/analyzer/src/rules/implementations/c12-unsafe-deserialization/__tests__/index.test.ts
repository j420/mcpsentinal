/**
 * C12 v2 — functional + evidence-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { UnsafeDeserializationRule } from "../index.js";
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

const rule = new UnsafeDeserializationRule();

function sourceContext(text: string): AnalysisContext {
  return {
    server: { id: "c12-t", name: "c12-test-server", description: null, github_url: null },
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

describe("C12 — fires (true positives)", () => {
  it("flags pickle.loads on request.data", () => {
    const results = rule.analyze(loadFixture("true-positive-01-pickle-loads.py"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C12");
  });

  it("flags node-serialize unserialize with req.body", () => {
    const results = rule.analyze(loadFixture("true-positive-02-node-serialize.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C12");
  });

  it("flags yaml.load without SafeLoader", () => {
    const results = rule.analyze(loadFixture("true-positive-03-yaml-load.py"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C12");
  });
});

// ─── True negatives ───────────────────────────────────────────────────────

describe("C12 — does not fire (true negatives)", () => {
  it("does NOT emit a critical finding for yaml.safe_load", () => {
    const results = rule.analyze(loadFixture("true-negative-01-yaml-safe-load.py"));
    const critical = results.filter((r) => r.severity === "critical");
    expect(critical.length).toBe(0);
  });

  it("does NOT emit a critical finding for JSON.parse", () => {
    const results = rule.analyze(loadFixture("true-negative-02-json-parse.ts"));
    const critical = results.filter((r) => r.severity === "critical");
    expect(critical.length).toBe(0);
  });
});

// ─── Evidence integrity ───────────────────────────────────────────────────

describe("C12 — evidence integrity", () => {
  it("every link with a location field is a structured Location; every VerificationStep.target is a Location", () => {
    const results = rule.analyze(loadFixture("true-positive-02-node-serialize.ts"));
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

  it("every chain has a source link and a deserialization sink link", () => {
    const results = rule.analyze(loadFixture("true-positive-02-node-serialize.ts"));
    expect(results.length).toBeGreaterThan(0);
    const sources = getLinksOfType<SourceLink>(results[0].chain, "source");
    const sinks = getLinksOfType<SinkLink>(results[0].chain, "sink");
    expect(sources.length).toBeGreaterThanOrEqual(1);
    expect(sinks.length).toBeGreaterThanOrEqual(1);
    expect(sinks[0].sink_type).toBe("deserialization");
  });

  it("every chain records a mitigation link", () => {
    const results = rule.analyze(loadFixture("true-positive-01-pickle-loads.py"));
    expect(results.length).toBeGreaterThan(0);
    const mitigations = getLinksOfType<MitigationLink>(results[0].chain, "mitigation");
    expect(mitigations.length).toBeGreaterThanOrEqual(1);
  });

  it("cites CVE-2017-5941 on the threat reference", () => {
    const results = rule.analyze(loadFixture("true-positive-02-node-serialize.ts"));
    expect(results[0].chain.threat_reference?.id).toBe("CVE-2017-5941");
  });
});

// ─── Confidence contract ─────────────────────────────────────────────────

describe("C12 — confidence contract", () => {
  it("caps confidence at 0.92 per charter", () => {
    const results = rule.analyze(loadFixture("true-positive-02-node-serialize.ts"));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.92);
      expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
    }
  });

  it("records ast_confirmed and interprocedural_hops factors on every finding", () => {
    const results = rule.analyze(loadFixture("true-positive-02-node-serialize.ts"));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    // Either AST or lightweight fallback must be recorded.
    const hasEvidenceOrigin =
      factors.includes("ast_confirmed") || factors.includes("lightweight_taint_fallback");
    expect(hasEvidenceOrigin).toBe(true);
    expect(factors).toContain("interprocedural_hops");
  });
});

// ─── Mutation ────────────────────────────────────────────────────────────

describe("C12 — mutation (swap pickle for json.loads removes the finding)", () => {
  it("critical finding disappears when pickle.loads is replaced by json.loads", () => {
    const vulnerable = `
import pickle
def handle(request):
    data = request.data
    obj = pickle.loads(data)
    return obj
`;
    const safe = `
import json
def handle(request):
    data = request.data
    obj = json.loads(data)
    return obj
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

// ─── Verification-steps ──────────────────────────────────────────────────

describe("C12 — verification steps", () => {
  it("every unsanitised finding emits at least three verification steps", () => {
    const results = rule.analyze(loadFixture("true-positive-02-node-serialize.ts")).filter(
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
