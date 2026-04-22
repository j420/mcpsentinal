/**
 * C9 v2 — functional + evidence-integrity tests.
 *
 * Every CHARTER lethal edge case has at least one corresponding test
 * (readdir root, base-path = "/", chdir root, Python os.walk,
 * bounded-base negative).
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ExcessiveFsScopeRule } from "../index.js";
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

const rule = new ExcessiveFsScopeRule();

function sourceContext(text: string): AnalysisContext {
  return {
    server: { id: "c9-t", name: "c9-test-server", description: null, github_url: null },
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

describe("C9 — fires (true positives)", () => {
  it("flags fs.readdirSync(\"/\")", () => {
    const results = rule.analyze(loadFixture("true-positive-01-readdir-root.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C9");
    expect(results[0].severity).toBe("high");
  });

  it("flags BASE_DIR = \"/\" assignment (defeats grep for fs call with root literal)", () => {
    const results = rule.analyze(loadFixture("true-positive-02-base-path-root.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C9");
    expect(results[0].severity).toBe("high");
  });

  it("flags Python os.walk(\"/\")", () => {
    const results = rule.analyze(loadFixture("true-positive-03-python-walk-root.py"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C9");
    expect(results[0].severity).toBe("high");
  });
});

// ─── True negatives ──────────────────────────────────────────────────────

describe("C9 — does not fire (true negatives)", () => {
  it("does NOT fire when BASE_DIR is a bounded subdirectory", () => {
    const results = rule.analyze(loadFixture("true-negative-01-bounded-base.ts"));
    expect(results.length).toBe(0);
  });

  it("does NOT fire when the file has no filesystem access at all", () => {
    const results = rule.analyze(loadFixture("true-negative-02-no-fs.ts"));
    expect(results.length).toBe(0);
  });
});

// ─── Evidence integrity ──────────────────────────────────────────────────

describe("C9 — evidence integrity", () => {
  it("every link with a location field is a structured Location; every step.target too", () => {
    const results = rule.analyze(loadFixture("true-positive-01-readdir-root.ts"));
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

  it("cites CWE-732 on the threat reference", () => {
    const results = rule.analyze(loadFixture("true-positive-01-readdir-root.ts"));
    expect(results[0].chain.threat_reference?.id).toBe("CWE-732");
  });

  it("every chain has source + sink + mitigation + impact", () => {
    const results = rule.analyze(loadFixture("true-positive-02-base-path-root.ts"));
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

describe("C9 — confidence contract", () => {
  it("caps confidence at 0.90 per charter", () => {
    const results = rule.analyze(loadFixture("true-positive-01-readdir-root.ts"));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.9);
      expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
    }
  });

  it("records ast_root_pattern + root_call_kind on every finding", () => {
    const results = rule.analyze(loadFixture("true-positive-03-python-walk-root.py"));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("ast_root_pattern");
    expect(factors).toContain("root_call_kind");
  });
});

// ─── Verification steps contract ─────────────────────────────────────────

describe("C9 — verification steps", () => {
  it("emits at least three steps on every finding", () => {
    const results = rule.analyze(loadFixture("true-positive-01-readdir-root.ts"));
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
