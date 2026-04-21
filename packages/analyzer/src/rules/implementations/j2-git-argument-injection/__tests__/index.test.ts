/**
 * J2 v2 — functional + evidence-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { GitArgumentInjectionRule } from "../index.js";
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

const rule = new GitArgumentInjectionRule();

function sourceContext(text: string): AnalysisContext {
  return {
    server: { id: "j2-t", name: "j2-test-server", description: null, github_url: null },
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

describe("J2 — fires (true positives)", () => {
  it("flags git clone with a template-literal repo argument", () => {
    const results = rule.analyze(loadFixture("true-positive-01-template-literal.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("J2");
  });

  it("flags git fetch with a --upload-pack flag from user input", () => {
    const results = rule.analyze(loadFixture("true-positive-02-upload-pack-flag.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("J2");
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("cve_2025_68145_flag_observed");
  });

  it("flags git diff with string concatenation of a user-controlled path", () => {
    const results = rule.analyze(loadFixture("true-positive-03-concat.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("J2");
  });
});

// ─── True negatives ───────────────────────────────────────────────────────

describe("J2 — does not fire (true negatives)", () => {
  it("does NOT flag execFile(\"git\", [\"status\"]) with hardcoded argv", () => {
    const results = rule.analyze(loadFixture("true-negative-01-execfile-array.ts"));
    expect(results.length).toBe(0);
  });

  it("does NOT flag a non-git exec call (that's C1 territory, not J2)", () => {
    const results = rule.analyze(loadFixture("true-negative-02-non-git-exec.ts"));
    expect(results.length).toBe(0);
  });
});

// ─── Evidence integrity ───────────────────────────────────────────────────

describe("J2 — evidence integrity", () => {
  it("every link with a location is a structured Location; every VerificationStep.target is a Location", () => {
    const results = rule.analyze(loadFixture("true-positive-01-template-literal.ts"));
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

  it("every chain has a source + command-execution sink link", () => {
    const results = rule.analyze(loadFixture("true-positive-02-upload-pack-flag.ts"));
    expect(results.length).toBeGreaterThan(0);
    const sources = getLinksOfType<SourceLink>(results[0].chain, "source");
    const sinks = getLinksOfType<SinkLink>(results[0].chain, "sink");
    expect(sources.length).toBeGreaterThanOrEqual(1);
    expect(sinks.length).toBeGreaterThanOrEqual(1);
    expect(sinks[0].sink_type).toBe("command-execution");
  });

  it("every chain records a mitigation link", () => {
    const results = rule.analyze(loadFixture("true-positive-01-template-literal.ts"));
    expect(results.length).toBeGreaterThan(0);
    const mitigations = getLinksOfType<MitigationLink>(results[0].chain, "mitigation");
    expect(mitigations.length).toBeGreaterThanOrEqual(1);
  });

  it("cites CVE-2025-68143 on the threat reference", () => {
    const results = rule.analyze(loadFixture("true-positive-01-template-literal.ts"));
    expect(results[0].chain.threat_reference?.id).toBe("CVE-2025-68143");
  });
});

// ─── Confidence ──────────────────────────────────────────────────────────

describe("J2 — confidence", () => {
  it("caps confidence at 0.93 per charter", () => {
    const results = rule.analyze(loadFixture("true-positive-01-template-literal.ts"));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.93);
      expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
    }
  });

  it("records git_specific_sink_confirmed + interprocedural_hops factors", () => {
    const results = rule.analyze(loadFixture("true-positive-01-template-literal.ts"));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    const hasEvidenceOrigin =
      factors.includes("ast_confirmed") || factors.includes("lightweight_taint_fallback");
    expect(hasEvidenceOrigin).toBe(true);
    expect(factors).toContain("git_specific_sink_confirmed");
    expect(factors).toContain("interprocedural_hops");
  });
});

// ─── Mutation ────────────────────────────────────────────────────────────

describe("J2 — mutation (swap exec('git ...') for execFile('git', [...]) removes the finding)", () => {
  it("critical finding disappears when argv is hardcoded", () => {
    const vulnerable = `
import { execSync } from "node:child_process";
export function f(req) {
  const repo = req.body.repo;
  return execSync(\`git clone \${repo}\`);
}
`;
    const safe = `
import { execFile } from "node:child_process";
export function f() {
  return execFile("git", ["status"]);
}
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

// ─── Verification steps ──────────────────────────────────────────────────

describe("J2 — verification steps", () => {
  it("every critical finding emits at least three verification steps", () => {
    const results = rule.analyze(loadFixture("true-positive-01-template-literal.ts")).filter(
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
