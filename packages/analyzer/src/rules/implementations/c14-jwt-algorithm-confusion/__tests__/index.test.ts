/**
 * C14 v2 — functional + evidence-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { JwtAlgorithmConfusionRule } from "../index.js";
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
const rule = new JwtAlgorithmConfusionRule();

function sourceContext(text: string): AnalysisContext {
  return {
    server: { id: "c14-t", name: "c14-test-server", description: null, github_url: null },
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

describe("C14 — fires (true positives)", () => {
  it("flags algorithms: ['RS256', 'none'] (algorithms-contains-none)", () => {
    const results = rule.analyze(loadFixture("true-positive-01-alg-none.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C14");
    expect(results[0].severity).toBe("critical");
  });

  it("flags jwt.verify(token, secret) with no options (verify-without-options)", () => {
    const results = rule.analyze(loadFixture("true-positive-02-no-options.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C14");
    expect(results[0].severity).toBe("critical");
  });

  it("flags PyJWT decode(verify=False)", () => {
    const results = rule.analyze(loadFixture("true-positive-03-pyjwt-verify-false.py"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C14");
    expect(results[0].severity).toBe("critical");
  });
});

// ─── True negatives ───────────────────────────────────────────────────────

describe("C14 — does not fire (true negatives)", () => {
  it("is silent when algorithms is pinned to ['RS256']", () => {
    const results = rule.analyze(loadFixture("true-negative-01-rs256-pinned.ts"));
    expect(results.length).toBe(0);
  });

  it("is silent on unrelated code with no JWT calls", () => {
    const results = rule.analyze(loadFixture("true-negative-02-unrelated.ts"));
    expect(results.length).toBe(0);
  });
});

// ─── CHARTER lethal edge cases ────────────────────────────────────────────

describe("C14 — CHARTER lethal edge cases", () => {
  it("ignore-expiration-true: flags ignoreExpiration: true (high severity)", () => {
    const text = `
import jwt from "jsonwebtoken";
export function a(t, k) {
  return jwt.verify(t, k, { algorithms: ["RS256"], ignoreExpiration: true });
}
`;
    const results = rule.analyze(sourceContext(text));
    expect(results.length).toBeGreaterThan(0);
    const igExp = results.find((r) =>
      r.chain.confidence_factors.some((f) => f.rationale.includes("ignore-expiration-true")),
    );
    expect(igExp).toBeDefined();
  });

  it("algorithms-reference-not-literal: flags algorithms as a variable reference", () => {
    const text = `
import jwt from "jsonwebtoken";
const opts = { algorithms: ALLOWED_ALGS };
export function a(t, k) {
  return jwt.verify(t, k, opts);
}
`;
    const results = rule.analyze(sourceContext(text));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C14");
  });
});

// ─── Evidence integrity ──────────────────────────────────────────────────

describe("C14 — evidence integrity", () => {
  it("every link with a location field is a structured Location; every step.target too", () => {
    const results = rule.analyze(loadFixture("true-positive-01-alg-none.ts"));
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
    const results = rule.analyze(loadFixture("true-positive-02-no-options.ts"));
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      expect(getLinksOfType<SourceLink>(r.chain, "source").length).toBeGreaterThanOrEqual(1);
      expect(getLinksOfType<SinkLink>(r.chain, "sink").length).toBeGreaterThanOrEqual(1);
      expect(getLinksOfType<MitigationLink>(r.chain, "mitigation").length).toBeGreaterThanOrEqual(1);
    }
  });

  it("cites CVE-2022-21449 on the threat reference", () => {
    const results = rule.analyze(loadFixture("true-positive-01-alg-none.ts"));
    expect(results[0].chain.threat_reference?.id).toBe("CVE-2022-21449");
  });

  it("every finding carries ≥4 verification steps", () => {
    const results = rule.analyze(loadFixture("true-positive-01-alg-none.ts"));
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

describe("C14 — confidence contract", () => {
  it("caps confidence at 0.92 per charter", () => {
    const results = rule.analyze(loadFixture("true-positive-01-alg-none.ts"));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.92);
      expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
    }
  });

  it("records jwt_call_identity + algorithms_option_inspection factors", () => {
    const results = rule.analyze(loadFixture("true-positive-01-alg-none.ts"));
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("jwt_call_identity");
    expect(factors).toContain("algorithms_option_inspection");
  });
});

// ─── Mutation: pinning algorithms removes the finding ────────────────────

describe("C14 — mutation (pinning algorithms to ['RS256'] removes the finding)", () => {
  it("the critical disappears when algorithms: ['none'] is replaced with ['RS256']", () => {
    const vulnerable = `
import jwt from "jsonwebtoken";
export function a(t, k) { return jwt.verify(t, k, { algorithms: ["none"] }); }
`;
    const safe = `
import jwt from "jsonwebtoken";
export function a(t, k) { return jwt.verify(t, k, { algorithms: ["RS256"] }); }
`;
    const vulnCritical = rule.analyze(sourceContext(vulnerable)).filter((r) => r.severity === "critical");
    const safeCritical = rule.analyze(sourceContext(safe)).filter((r) => r.severity === "critical");
    expect(vulnCritical.length).toBeGreaterThan(0);
    expect(safeCritical.length).toBe(0);
  });
});
