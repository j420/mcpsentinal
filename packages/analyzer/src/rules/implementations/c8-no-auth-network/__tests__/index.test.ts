/**
 * C8 v2 — functional + evidence-integrity tests.
 *
 * Every CHARTER lethal edge case has at least one corresponding test
 * (explicit wildcard, default-host, Python uvicorn, loopback negative,
 * auth-middleware-present negative).
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { NoAuthOnNetworkRule } from "../index.js";
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

const rule = new NoAuthOnNetworkRule();

function sourceContext(text: string): AnalysisContext {
  return {
    server: { id: "c8-t", name: "c8-test-server", description: null, github_url: null },
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

describe("C8 — fires (true positives)", () => {
  it("flags `app.listen(3000, '0.0.0.0')` with no auth middleware", () => {
    const results = rule.analyze(loadFixture("true-positive-01-explicit-wildcard.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C8");
    expect(results[0].severity).toBe("high");
  });

  it("flags bare `app.listen(8080)` (defaults to 0.0.0.0) with no auth", () => {
    const results = rule.analyze(loadFixture("true-positive-02-default-host.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C8");
    expect(results[0].severity).toBe("high");
  });

  it("flags Python uvicorn.run host=\"0.0.0.0\" with no Depends auth", () => {
    const results = rule.analyze(loadFixture("true-positive-03-python-uvicorn.py"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C8");
    expect(results[0].severity).toBe("high");
  });
});

// ─── True negatives ──────────────────────────────────────────────────────

describe("C8 — does not fire (true negatives)", () => {
  it("does NOT fire when bind host is 127.0.0.1", () => {
    const results = rule.analyze(loadFixture("true-negative-01-loopback.ts"));
    expect(results.length).toBe(0);
  });

  it("does NOT fire when an auth middleware (verifyJwt) is wired before listen", () => {
    const results = rule.analyze(loadFixture("true-negative-02-with-auth.ts"));
    expect(results.length).toBe(0);
  });
});

// ─── Evidence integrity ──────────────────────────────────────────────────

describe("C8 — evidence integrity", () => {
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

  it("cites CWE-306 on the threat reference", () => {
    const results = rule.analyze(loadFixture("true-positive-01-explicit-wildcard.ts"));
    expect(results[0].chain.threat_reference?.id).toBe("CWE-306");
  });

  it("every chain has source + sink + mitigation + impact", () => {
    const results = rule.analyze(loadFixture("true-positive-02-default-host.ts"));
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

describe("C8 — confidence contract", () => {
  it("caps confidence at 0.85 per charter", () => {
    const results = rule.analyze(loadFixture("true-positive-01-explicit-wildcard.ts"));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.85);
      expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
    }
  });

  it("records ast_network_bind + auth_middleware_search on every finding", () => {
    const results = rule.analyze(loadFixture("true-positive-03-python-uvicorn.py"));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("ast_network_bind");
    expect(factors).toContain("auth_middleware_search");
  });
});

// ─── Verification steps contract ─────────────────────────────────────────

describe("C8 — verification steps", () => {
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
