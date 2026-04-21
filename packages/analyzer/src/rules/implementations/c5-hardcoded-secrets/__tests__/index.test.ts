/**
 * C5 v2 — functional + evidence-integrity tests.
 *
 * Every CHARTER lethal edge case has at least one corresponding test.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { HardcodedSecretsRule } from "../index.js";
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

const rule = new HardcodedSecretsRule();

function makeContext(file: string, text: string): AnalysisContext {
  return {
    server: { id: "c5-t", name: "c5-test-server", description: null, github_url: null },
    tools: [],
    source_code: text,
    source_files: new Map([[file, text]]),
    dependencies: [],
    connection_metadata: null,
  };
}

function loadFixture(name: string): AnalysisContext {
  const full = join(FIX, name);
  return makeContext(full, readFileSync(full, "utf8"));
}

function getLinksOfType<T extends { type: string }>(chain: EvidenceChain, type: string): T[] {
  return chain.links.filter((l) => l.type === type) as T[];
}

// ─── True positives ───────────────────────────────────────────────────────

describe("C5 — fires (true positives)", () => {
  it("flags an OpenAI sk- API key hardcoded in TypeScript", () => {
    const results = rule.analyze(loadFixture("true-positive-01-openai-key.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C5");
    expect(results[0].severity).toBe("critical");
  });

  it("flags an AWS AKIA permanent access key ID", () => {
    const results = rule.analyze(loadFixture("true-positive-02-aws-akia.ts"));
    expect(results.length).toBeGreaterThan(0);
    const akiaHit = results.find((r) => {
      const source = getLinksOfType<SourceLink>(r.chain, "source")[0];
      return source?.observed.includes("AKIA");
    });
    expect(akiaHit).toBeDefined();
    expect(akiaHit?.severity).toBe("critical");
  });

  it("flags an Anthropic sk-ant- API key in Python", () => {
    const results = rule.analyze(loadFixture("true-positive-03-anthropic-key.py"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C5");
    expect(results[0].severity).toBe("critical");
  });
});

// ─── True negatives ──────────────────────────────────────────────────────

describe("C5 — does not fire (true negatives)", () => {
  it("is silent when the credential is loaded from process.env", () => {
    const results = rule.analyze(loadFixture("true-negative-01-env-loaded.ts"));
    // No string literal matched a token prefix.
    const critical = results.filter((r) => r.severity === "critical");
    expect(critical.length).toBe(0);
  });

  it("is silent when a placeholder marker is on the same line (REPLACE-ME)", () => {
    const results = rule.analyze(loadFixture("true-negative-02-placeholder.ts"));
    expect(results.length).toBe(0);
  });

  it("is silent inside an .env.example file (filename-based skip)", () => {
    const results = rule.analyze(loadFixture("true-negative-03-example-file.env.example"));
    expect(results.length).toBe(0);
  });
});

// ─── Evidence integrity (Rule Standard v2 §2, §4) ────────────────────────

describe("C5 — evidence integrity", () => {
  it("every link with a location field is a structured Location, every step.target too", () => {
    const results = rule.analyze(loadFixture("true-positive-01-openai-key.ts"));
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
    const results = rule.analyze(loadFixture("true-positive-02-aws-akia.ts"));
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      expect(getLinksOfType<SourceLink>(r.chain, "source").length).toBeGreaterThanOrEqual(1);
      expect(getLinksOfType<SinkLink>(r.chain, "sink").length).toBeGreaterThanOrEqual(1);
      expect(getLinksOfType<MitigationLink>(r.chain, "mitigation").length).toBeGreaterThanOrEqual(1);
    }
  });

  it("cites CWE-798 on every finding", () => {
    const results = rule.analyze(loadFixture("true-positive-01-openai-key.ts"));
    for (const r of results) {
      expect(r.chain.threat_reference?.id).toBe("CWE-798");
    }
  });

  it("confidence is in [0.05, 0.85]", () => {
    const results = rule.analyze(loadFixture("true-positive-02-aws-akia.ts"));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.85);
      expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
    }
  });

  it("every unsuppressed finding emits ≥3 verification steps", () => {
    const results = rule.analyze(loadFixture("true-positive-01-openai-key.ts"));
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

// ─── CHARTER lethal edge-case coverage ────────────────────────────────────

describe("C5 — CHARTER lethal edge cases", () => {
  it("test-nature-structural: a file importing vitest + calling describe() is skipped", () => {
    const text = `
import { describe, it } from "vitest";
const apiKey = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJ";
describe("t", () => { it("x", () => {}); });
`;
    const ctx = makeContext("src/example-not-test-ext.ts", text);
    const results = rule.analyze(ctx);
    expect(results.length).toBe(0);
  });

  it("placeholder-marker-detection: per-line REPLACE-ME suppresses the finding", () => {
    const text = `
const apiKey = "sk-proj-REPLACE-ME-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
`;
    const ctx = makeContext("src/config.ts", text);
    const results = rule.analyze(ctx);
    expect(results.length).toBe(0);
  });

  it("prefix-literal-recognition: at least 14 known formats, GitHub PAT fires", () => {
    const text = `const githubPat = "ghp_abcdefghijklmnopqrstuvwxyz1234567890AB";`;
    const ctx = makeContext("src/gh.ts", text);
    const results = rule.analyze(ctx);
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].severity).toBe("critical");
  });

  it("entropy-minimum-threshold: low-entropy generic identifier value is skipped", () => {
    // A generic api_key assignment whose value is 12 repeated chars has
    // Shannon entropy ≈ 0 bits/char — far below the 3.5 floor.
    const text = `const api_key = "aaaaaaaaaaaaaaaa";`;
    const ctx = makeContext("src/low-entropy.ts", text);
    const results = rule.analyze(ctx);
    expect(results.length).toBe(0);
  });

  it("entropy-bonus-high: high-entropy matches emit an entropy_score factor with positive adjustment", () => {
    const results = rule.analyze(loadFixture("true-positive-01-openai-key.ts"));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors;
    const entropyFactor = factors.find((f) => f.factor === "entropy_score");
    expect(entropyFactor).toBeDefined();
    expect(entropyFactor!.adjustment).toBeGreaterThan(0);
  });

  it("comment-line-skip: a credential inside a // comment does not fire", () => {
    const text = `
// Historical API key (rotated 2023): sk-proj-abcdefghijklmnopqrstuvwxyz1234567890
export function run() {}
`;
    const ctx = makeContext("src/notes.ts", text);
    const results = rule.analyze(ctx);
    // The AST walker never visits comment text, so no StringLiteral is found in the comment.
    expect(results.length).toBe(0);
  });
});
