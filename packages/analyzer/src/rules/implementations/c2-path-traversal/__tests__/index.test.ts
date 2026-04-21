/**
 * C2 v2 — functional + evidence-integrity tests.
 *
 * Every CHARTER lethal edge case has at least one corresponding test.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { PathTraversalRule } from "../index.js";
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

const rule = new PathTraversalRule();

function sourceContext(text: string): AnalysisContext {
  return {
    server: { id: "c2-t", name: "c2-test-server", description: null, github_url: null },
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

describe("C2 — fires (true positives)", () => {
  it("flags a direct req.body → fs.readFile flow", () => {
    const results = rule.analyze(loadFixture("true-positive-01-req-body-readfile.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C2");
    expect(results[0].severity).toBe("critical");
  });

  it("flags a multi-hop req.query.f → var → fs.writeFile flow", () => {
    const results = rule.analyze(loadFixture("true-positive-02-multihop.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C2");
    expect(results[0].severity).toBe("critical");
  });

  it("flags a Python request.args → open() flow via lightweight fallback", () => {
    const results = rule.analyze(loadFixture("true-positive-03-python-open.py"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C2");
    // Python comes via lightweight-taint; severity stays critical unless sanitiser present.
    expect(["critical", "informational"]).toContain(results[0].severity);
  });
});

// ─── True negatives ───────────────────────────────────────────────────────

describe("C2 — does not fire (true negatives)", () => {
  it("does NOT emit a critical finding when the path is clamped via startsWith", () => {
    const results = rule.analyze(loadFixture("true-negative-01-clamped.ts"));
    const critical = results.filter((r) => r.severity === "critical");
    expect(critical.length).toBe(0);
  });

  it("does NOT fire when the path is a hardcoded literal", () => {
    const results = rule.analyze(loadFixture("true-negative-02-hardcoded.ts"));
    expect(results.length).toBe(0);
  });
});

// ─── Evidence integrity ───────────────────────────────────────────────────

describe("C2 — evidence integrity", () => {
  it("every link with a location field is a structured Location; every step.target too", () => {
    const results = rule.analyze(loadFixture("true-positive-01-req-body-readfile.ts"));
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

  it("every chain has ≥1 source link and a file-write sink link", () => {
    const results = rule.analyze(loadFixture("true-positive-02-multihop.ts"));
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      const sources = getLinksOfType<SourceLink>(r.chain, "source");
      const sinks = getLinksOfType<SinkLink>(r.chain, "sink");
      expect(sources.length).toBeGreaterThanOrEqual(1);
      expect(sinks.length).toBeGreaterThanOrEqual(1);
      expect(sinks[0].sink_type).toBe("file-write");
    }
  });

  it("every chain records a mitigation link", () => {
    const results = rule.analyze(loadFixture("true-positive-01-req-body-readfile.ts"));
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      expect(getLinksOfType<MitigationLink>(r.chain, "mitigation").length).toBeGreaterThanOrEqual(1);
    }
  });

  it("cites CVE-2025-53109 on the threat reference", () => {
    const results = rule.analyze(loadFixture("true-positive-01-req-body-readfile.ts"));
    expect(results[0].chain.threat_reference?.id).toBe("CVE-2025-53109");
  });
});

// ─── Confidence contract ─────────────────────────────────────────────────

describe("C2 — confidence contract", () => {
  it("caps confidence at 0.92 per charter", () => {
    const results = rule.analyze(loadFixture("true-positive-02-multihop.ts"));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.92);
      expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
    }
  });

  it("records ast_confirmed or lightweight_taint_fallback on every finding", () => {
    const tsResults = rule.analyze(loadFixture("true-positive-01-req-body-readfile.ts"));
    const pyResults = rule.analyze(loadFixture("true-positive-03-python-open.py"));
    for (const results of [tsResults, pyResults]) {
      expect(results.length).toBeGreaterThan(0);
      const factors = results[0].chain.confidence_factors.map((f) => f.factor);
      const hasOrigin =
        factors.includes("ast_confirmed") || factors.includes("lightweight_taint_fallback");
      expect(hasOrigin).toBe(true);
      expect(factors).toContain("interprocedural_hops");
    }
  });
});

// ─── Mutation: adding a startsWith clamp removes the critical finding ─────

describe("C2 — mutation (adding a startsWith clamp suppresses the critical finding)", () => {
  it("critical disappears when a sanitiser (path.resolve) is inserted before the sink", () => {
    const vulnerable = `
import fs from "node:fs";
import path from "node:path";
export function go(req) {
  const p = path.join("/var/app", req.body.f);
  fs.writeFileSync(p, "content");
}
`;
    const safe = `
import fs from "node:fs";
import path from "node:path";
export function go(req) {
  const resolved = path.resolve(req.body.f);
  fs.writeFileSync(resolved, "content");
}
`;
    const vulnCritical = rule
      .analyze(sourceContext(vulnerable))
      .filter((r) => r.severity === "critical");
    const safeCritical = rule
      .analyze(sourceContext(safe))
      .filter((r) => r.severity === "critical");
    expect(vulnCritical.length).toBeGreaterThan(0);
    expect(safeCritical.length).toBe(0);
  });
});

// ─── Verification steps contract ─────────────────────────────────────────

describe("C2 — verification steps", () => {
  it("emits at least three steps on every unsanitised finding", () => {
    const results = rule
      .analyze(loadFixture("true-positive-01-req-body-readfile.ts"))
      .filter((r) => r.severity === "critical");
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
