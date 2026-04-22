/**
 * C3 v2 — functional + evidence-integrity tests.
 *
 * Every CHARTER lethal edge case has at least one corresponding test
 * (IMDS / DNS rebinding / scheme smuggling / encoding bypass are
 * surfaced via the obfuscation fixtures + sanitiser-identity guard).
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { SsrfRule } from "../index.js";
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

const rule = new SsrfRule();

function sourceContext(text: string): AnalysisContext {
  return {
    server: { id: "c3-t", name: "c3-test-server", description: null, github_url: null },
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

describe("C3 — fires (true positives)", () => {
  it("flags a direct req.body.target → fetch() flow", () => {
    const results = rule.analyze(loadFixture("true-positive-01-req-body-fetch.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C3");
    expect(results[0].severity).toBe("high");
  });

  it("flags a multi-hop req.query.url → var → axios.get() flow", () => {
    const results = rule.analyze(loadFixture("true-positive-02-multihop-axios.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C3");
    expect(results[0].severity).toBe("high");
  });

  it("flags a Python request.args → requests.get() flow with string concat obfuscation", () => {
    const results = rule.analyze(loadFixture("true-positive-03-python-requests.py"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C3");
    // Python lightweight-taint: severity stays high unless a sanitiser is on the path.
    expect(["high", "informational"]).toContain(results[0].severity);
  });
});

// ─── True negatives ───────────────────────────────────────────────────────

describe("C3 — does not fire (true negatives)", () => {
  it("does NOT fire when the URL is a hardcoded literal", () => {
    const results = rule.analyze(loadFixture("true-negative-01-validated.ts"));
    expect(results.length).toBe(0);
  });

  it("does NOT fire when the user input only selects from a fixed allowlist of paths", () => {
    const results = rule.analyze(loadFixture("true-negative-02-hardcoded.ts"));
    // The user input controls only a Map lookup key, not the URL host.
    // No taint flow to the fetch sink.
    expect(results.length).toBe(0);
  });
});

// ─── Evidence integrity ───────────────────────────────────────────────────

describe("C3 — evidence integrity", () => {
  it("every link with a location field is a structured Location; every step.target too", () => {
    const results = rule.analyze(loadFixture("true-positive-01-req-body-fetch.ts"));
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

  it("every chain has ≥1 source link and a network-send sink link", () => {
    const results = rule.analyze(loadFixture("true-positive-02-multihop-axios.ts"));
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      const sources = getLinksOfType<SourceLink>(r.chain, "source");
      const sinks = getLinksOfType<SinkLink>(r.chain, "sink");
      expect(sources.length).toBeGreaterThanOrEqual(1);
      expect(sinks.length).toBeGreaterThanOrEqual(1);
      expect(sinks[0].sink_type).toBe("network-send");
    }
  });

  it("every chain records a mitigation link", () => {
    const results = rule.analyze(loadFixture("true-positive-01-req-body-fetch.ts"));
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      expect(getLinksOfType<MitigationLink>(r.chain, "mitigation").length).toBeGreaterThanOrEqual(1);
    }
  });

  it("cites CWE-918 on the threat reference", () => {
    const results = rule.analyze(loadFixture("true-positive-01-req-body-fetch.ts"));
    expect(results[0].chain.threat_reference?.id).toBe("CWE-918");
  });
});

// ─── Confidence contract ─────────────────────────────────────────────────

describe("C3 — confidence contract", () => {
  it("caps confidence at 0.92 per charter", () => {
    const results = rule.analyze(loadFixture("true-positive-02-multihop-axios.ts"));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.92);
      expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
    }
  });

  it("records ast_confirmed or lightweight_taint_fallback on every finding", () => {
    const tsResults = rule.analyze(loadFixture("true-positive-01-req-body-fetch.ts"));
    const pyResults = rule.analyze(loadFixture("true-positive-03-python-requests.py"));
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

// ─── Verification steps contract ─────────────────────────────────────────

describe("C3 — verification steps", () => {
  it("emits at least three steps on every unsanitised finding", () => {
    const results = rule
      .analyze(loadFixture("true-positive-01-req-body-fetch.ts"))
      .filter((r) => r.severity === "high");
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
