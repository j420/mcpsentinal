import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { AgentCredentialPropagationRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function loadFixture(name: string) {
  const file = join(FIXTURES_DIR, name);
  return { file, text: readFileSync(file, "utf8") };
}

function makeContext(file: string, text: string): AnalysisContext {
  return {
    server: { id: "srv-1", name: "test", description: null, github_url: null },
    tools: [],
    source_code: text,
    source_files: new Map([[file, text]]),
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new AgentCredentialPropagationRule();

// ─── true positives ────────────────────────────────────────────────────────

describe("K14 — fires (true positives)", () => {
  it("flags direct credential write to sharedStore", () => {
    const { file, text } = loadFixture("true-positive-01-direct-credential-write.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("K14");
    expect(results[0].severity).toBe("critical");
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("credential_identifier_observed");
    expect(factors).toContain("shared_state_sink_observed");
    expect(factors).toContain("no_redaction_in_scope");
  });

  it("flags encoder-wrapped credential (Buffer.from(token).toString)", () => {
    const { file, text } = loadFixture("true-positive-02-encoder-wrapped.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("encoder-passthrough-taint");
  });

  it("flags credential write through an alias binding", () => {
    const { file, text } = loadFixture("true-positive-03-alias-binding.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("alias-binding-resolution");
  });
});

// ─── true negatives ────────────────────────────────────────────────────────

describe("K14 — does not fire (true negatives)", () => {
  it("recognises vault.seal redactor in enclosing scope", () => {
    const { file, text } = loadFixture("true-negative-01-redacted-credential.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });

  it("ignores per-agent private store (not cross-agent)", () => {
    const { file, text } = loadFixture("true-negative-02-private-store.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });

  it("suppresses placeholder literal RHS (placeholder-literal-suppression)", () => {
    const inline =
      `declare const sharedStore: { set(k: string, v: unknown): void };\n` +
      `export function init(): void { sharedStore.set("auth", "REPLACE_ME"); }\n`;
    const ctx = makeContext("inline.ts", inline);
    expect(rule.analyze(ctx)).toEqual([]);
  });

  it("skips a structurally-identified test file", () => {
    const inline =
      `import { describe, it } from "vitest";\n` +
      `declare const sharedStore: { set(k: string, v: unknown): void };\n` +
      `describe("auth", () => {\n` +
      `  it("persists token", () => {\n` +
      `    const token = "fake";\n` +
      `    sharedStore.set("auth", token);\n` +
      `  });\n` +
      `});\n`;
    const ctx = makeContext("auth.test.ts", inline);
    expect(rule.analyze(ctx)).toEqual([]);
  });
});

// ─── v2 chain-integrity contract ───────────────────────────────────────────

describe("K14 — v2 chain-integrity contract", () => {
  const fixtures = readdirSync(FIXTURES_DIR).filter((n) => n.startsWith("true-positive-"));
  for (const name of fixtures) {
    it(`${name} → every link has a structured Location`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        for (const link of r.chain.links) {
          if (link.type === "impact") continue;
          expect(isLocation(link.location)).toBe(true);
        }
      }
    });

    it(`${name} → every verification step target is a Location`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      for (const r of results) {
        const steps = r.chain.verification_steps ?? [];
        expect(steps.length).toBeGreaterThan(0);
        for (const step of steps) expect(isLocation(step.target)).toBe(true);
      }
    });

    it(`${name} → confidence capped at 0.88`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.88);
      }
    });

    it(`${name} → threat reference cites Invariant Labs 2026`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      for (const r of results) {
        expect(r.chain.threat_reference?.id).toBe(
          "InvariantLabs-CrossAgentMCPMemory-2026",
        );
      }
    });
  }
});

// ─── confidence ordering ───────────────────────────────────────────────────

describe("K14 — confidence ordering", () => {
  it("encoder-wrapped + helper combo accumulates more strategy factors than direct", () => {
    const direct = loadFixture("true-positive-01-direct-credential-write.ts");
    const encoder = loadFixture("true-positive-02-encoder-wrapped.ts");
    const directRes = rule.analyze(makeContext(direct.file, direct.text));
    const encoderRes = rule.analyze(makeContext(encoder.file, encoder.text));

    const directStrategyFactors = directRes[0].chain.confidence_factors.filter(
      (f) =>
        f.factor === "encoder-passthrough-taint" ||
        f.factor === "alias-binding-resolution" ||
        f.factor === "cross-function-helper-walk",
    );
    const encoderStrategyFactors = encoderRes[0].chain.confidence_factors.filter(
      (f) =>
        f.factor === "encoder-passthrough-taint" ||
        f.factor === "alias-binding-resolution" ||
        f.factor === "cross-function-helper-walk",
    );

    // Direct write has zero strategy factors (it's the baseline);
    // encoder-wrapped adds the encoder-passthrough-taint factor.
    expect(directStrategyFactors.length).toBe(0);
    expect(encoderStrategyFactors.length).toBeGreaterThan(0);
  });
});

// ─── mutation: swap sink to non-shared store ───────────────────────────────

describe("K14 — mutation guard", () => {
  it("TP1 with sink swapped to a non-shared store does not fire", () => {
    const original = loadFixture("true-positive-01-direct-credential-write.ts");
    const mutated = original.text.replace(/sharedStore/g, "agentLocalCache");
    const ctx = makeContext("mutated.ts", mutated);
    expect(rule.analyze(ctx)).toEqual([]);
  });
});
