/**
 * C10 v2 — functional + evidence-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { PrototypePollutionRule } from "../index.js";
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
const rule = new PrototypePollutionRule();

function sourceContext(text: string): AnalysisContext {
  return {
    server: { id: "c10-t", name: "c10-test-server", description: null, github_url: null },
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

describe("C10 — fires (true positives)", () => {
  it("flags lodash _.merge with req.body input", () => {
    const results = rule.analyze(loadFixture("true-positive-01-lodash-merge.ts"));
    expect(results.length).toBeGreaterThan(0);
    const critical = results.filter((r) => r.severity === "critical");
    expect(critical.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C10");
  });

  it("flags Object.assign with JSON.parse(req.body)", () => {
    const results = rule.analyze(loadFixture("true-positive-02-object-assign-jsonparse.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C10");
  });

  it("flags a literal target['__proto__'] write (critical-key)", () => {
    const results = rule.analyze(loadFixture("true-positive-03-critical-key.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].severity).toBe("critical");
  });
});

// ─── True negatives ───────────────────────────────────────────────────────

describe("C10 — does not fire (true negatives)", () => {
  it("does NOT emit a critical finding when the merge target is Object.create(null)", () => {
    const results = rule.analyze(loadFixture("true-negative-01-null-proto-target.ts"));
    const critical = results.filter((r) => r.severity === "critical");
    expect(critical.length).toBe(0);
  });

  it("is silent when all merge inputs are module-local constants", () => {
    const results = rule.analyze(loadFixture("true-negative-02-no-user-input.ts"));
    expect(results.length).toBe(0);
  });
});

// ─── Evidence integrity ───────────────────────────────────────────────────

describe("C10 — evidence integrity", () => {
  it("every link with a location field is a structured Location; every step.target too", () => {
    const results = rule.analyze(loadFixture("true-positive-01-lodash-merge.ts"));
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

  it("every chain has ≥1 source, ≥1 sink, and a mitigation link", () => {
    const results = rule.analyze(loadFixture("true-positive-02-object-assign-jsonparse.ts"));
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      expect(getLinksOfType<SourceLink>(r.chain, "source").length).toBeGreaterThanOrEqual(1);
      expect(getLinksOfType<SinkLink>(r.chain, "sink").length).toBeGreaterThanOrEqual(1);
      expect(getLinksOfType<MitigationLink>(r.chain, "mitigation").length).toBeGreaterThanOrEqual(1);
    }
  });

  it("cites CVE-2019-10744 on the threat reference", () => {
    const results = rule.analyze(loadFixture("true-positive-01-lodash-merge.ts"));
    expect(results[0].chain.threat_reference?.id).toBe("CVE-2019-10744");
  });

  it("every finding carries ≥4 verification steps", () => {
    const results = rule.analyze(loadFixture("true-positive-01-lodash-merge.ts"));
    for (const r of results) {
      const steps = r.chain.verification_steps as VerificationStep[];
      expect(steps.length).toBeGreaterThanOrEqual(4);
      for (const s of steps) {
        expect(isLocation(s.target)).toBe(true);
        expect(s.instruction.length).toBeGreaterThan(20);
      }
    }
  });
});

// ─── Confidence contract ─────────────────────────────────────────────────

describe("C10 — confidence contract", () => {
  it("caps confidence at 0.92 per charter", () => {
    const results = rule.analyze(loadFixture("true-positive-01-lodash-merge.ts"));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.92);
      expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
    }
  });

  it("records sink_function_identity + tainted_source_proximity factors on every finding", () => {
    const results = rule.analyze(loadFixture("true-positive-01-lodash-merge.ts"));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("sink_function_identity");
    expect(factors).toContain("tainted_source_proximity");
    expect(factors).toContain("hasownproperty_guard_present");
  });
});

// ─── CHARTER lethal edge case: dynamic-key write with tainted key ─────────

describe("C10 — CHARTER: dynamic-key write with tainted key", () => {
  it("flags obj[key] = v where key came from req.body", () => {
    const text = `
export function handle(req) {
  const obj = {};
  const key = req.body.k;
  obj[key] = req.body.v;
}
`;
    const results = rule.analyze(sourceContext(text));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C10");
  });
});

// ─── Mutation: adding Object.create(null) removes critical ───────────────

describe("C10 — mutation (null-proto target removes the critical finding)", () => {
  it("the critical disappears when the merge target is swapped to Object.create(null)", () => {
    const vulnerable = `
import _ from "lodash";
export function go(req) {
  const cfg = {};
  return _.merge(cfg, req.body.settings);
}
`;
    const safe = `
import _ from "lodash";
export function go(req) {
  const cfg = Object.create(null);
  return _.merge(cfg, req.body.settings);
}
`;
    const vulnCritical = rule.analyze(sourceContext(vulnerable)).filter((r) => r.severity === "critical");
    const safeCritical = rule.analyze(sourceContext(safe)).filter((r) => r.severity === "critical");
    expect(vulnCritical.length).toBeGreaterThan(0);
    expect(safeCritical.length).toBe(0);
  });
});
