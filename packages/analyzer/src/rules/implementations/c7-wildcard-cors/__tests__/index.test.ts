/**
 * C7 v2 — functional + evidence-integrity tests.
 *
 * Every CHARTER lethal edge case has at least one corresponding test
 * (explicit wildcard, reflected origin, setHeader bypass, credentials
 * combo).
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { WildcardCorsRule } from "../index.js";
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

const rule = new WildcardCorsRule();

function sourceContext(text: string): AnalysisContext {
  return {
    server: { id: "c7-t", name: "c7-test-server", description: null, github_url: null },
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

describe("C7 — fires (true positives)", () => {
  it("flags `cors({ origin: '*', credentials: true })` (highest-impact)", () => {
    const results = rule.analyze(loadFixture("true-positive-01-explicit-wildcard.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C7");
    expect(results[0].severity).toBe("high");
    // Credentials flag escalates impact_type to session-hijack
    const sinks = getLinksOfType<SinkLink>(results[0].chain, "sink");
    expect(sinks[0].cve_precedent).toBe("CWE-942");
  });

  it("flags reflected origin via callback returning true unconditionally", () => {
    const results = rule.analyze(loadFixture("true-positive-02-reflected-origin.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C7");
    expect(results[0].severity).toBe("high");
  });

  it("flags manual setHeader('Access-Control-Allow-Origin', '*') bypass", () => {
    const results = rule.analyze(loadFixture("true-positive-03-set-header-wildcard.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C7");
    expect(results[0].severity).toBe("high");
  });
});

// ─── True negatives ──────────────────────────────────────────────────────

describe("C7 — does not fire (true negatives)", () => {
  it("does NOT fire when CORS is configured with an explicit allowlist", () => {
    const results = rule.analyze(loadFixture("true-negative-01-allowlist.ts"));
    expect(results.length).toBe(0);
  });

  it("does NOT fire when the file has no CORS configuration at all", () => {
    const results = rule.analyze(loadFixture("true-negative-02-no-cors.ts"));
    expect(results.length).toBe(0);
  });
});

// ─── Evidence integrity ──────────────────────────────────────────────────

describe("C7 — evidence integrity", () => {
  it("every link with a location field is a structured Location; every step.target too", () => {
    const results = rule.analyze(loadFixture("true-positive-01-explicit-wildcard.ts"));
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

  it("every chain has source + sink + mitigation + reference", () => {
    const results = rule.analyze(loadFixture("true-positive-02-reflected-origin.ts"));
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      const sources = getLinksOfType<SourceLink>(r.chain, "source");
      const sinks = getLinksOfType<SinkLink>(r.chain, "sink");
      const mits = getLinksOfType<MitigationLink>(r.chain, "mitigation");
      expect(sources.length).toBeGreaterThanOrEqual(1);
      expect(sinks.length).toBeGreaterThanOrEqual(1);
      expect(mits.length).toBeGreaterThanOrEqual(1);
      expect(r.chain.threat_reference?.id).toBe("CWE-942");
    }
  });
});

// ─── Confidence contract ─────────────────────────────────────────────────

describe("C7 — confidence contract", () => {
  it("caps confidence at 0.90 per charter", () => {
    const results = rule.analyze(loadFixture("true-positive-01-explicit-wildcard.ts"));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.9);
      expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
    }
  });

  it("records ast_cors_pattern on every finding", () => {
    const results = rule.analyze(loadFixture("true-positive-03-set-header-wildcard.ts"));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("ast_cors_pattern");
    expect(factors).toContain("cors_credentials_flag");
  });
});

// ─── Verification steps contract ─────────────────────────────────────────

describe("C7 — verification steps", () => {
  it("emits at least three steps on every finding", () => {
    const results = rule.analyze(loadFixture("true-positive-01-explicit-wildcard.ts"));
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
