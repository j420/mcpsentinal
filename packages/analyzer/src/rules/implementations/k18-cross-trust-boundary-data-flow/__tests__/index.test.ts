import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { K18CrossTrustBoundaryDataFlowRule } from "../index.js";
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

const rule = new K18CrossTrustBoundaryDataFlowRule();

describe("K18 — fires (true positives)", () => {
  it("flags process.env.SECRET_KEY flowing to res.json", () => {
    const { file, text } = loadFixture("true-positive-01-env-secret-to-response.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("K18");
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("sensitive_source_env_secret");
    expect(factors).toContain("external_sink_reached");
  });

  it("flags vault.getCredential() flowing to return", () => {
    const { file, text } = loadFixture("true-positive-02-credential-call-to-return.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("sensitive_source_credential_call");
  });

  it("flags sensitive file path flowing to outbound POST", () => {
    const { file, text } = loadFixture("true-positive-03-sensitive-path-to-network.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("sensitive_source_sensitive_path");
  });
});

describe("K18 — does not fire (true negatives)", () => {
  it("accepts redactor applied to the same identifier that reaches the response", () => {
    const { file, text } = loadFixture("true-negative-01-redactor-on-same-variable.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });

  it("skips a structurally-identified test file", () => {
    const { file, text } = loadFixture("true-negative-02-test-file.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });
});

describe("K18 — evidence integrity contract", () => {
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
        expect(steps.length).toBeGreaterThanOrEqual(3);
        for (const step of steps) expect(isLocation(step.target)).toBe(true);
      }
    });
  }
});

describe("K18 — confidence & ordering", () => {
  it("env-secret source confidence ≥ sensitive-param-only confidence", () => {
    const { file: f1, text: t1 } = loadFixture("true-positive-01-env-secret-to-response.ts");
    const r1 = rule.analyze(makeContext(f1, t1));

    const paramOnlySrc =
      "export function f(password: string, res: { json(b: unknown): void }): void { res.json({ password }); }\n";
    const r2 = rule.analyze(makeContext("p.ts", paramOnlySrc));

    expect(r1.length).toBeGreaterThan(0);
    expect(r2.length).toBeGreaterThan(0);
    expect(r1[0].chain.confidence).toBeGreaterThanOrEqual(r2[0].chain.confidence);
  });

  it("confidence capped at 0.88", () => {
    const fixtures = readdirSync(FIXTURES_DIR).filter((n) => n.startsWith("true-positive-"));
    for (const name of fixtures) {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.88);
      }
    }
  });

  it("threat reference cites CoSAI-MCP-T5", () => {
    const { file, text } = loadFixture("true-positive-01-env-secret-to-response.ts");
    const results = rule.analyze(makeContext(file, text));
    for (const r of results) expect(r.chain.threat_reference?.id).toBe("CoSAI-MCP-T5");
  });
});

describe("K18 — mutation test", () => {
  it("TP-01 flips to benign when redact() is applied to the returned identifier", () => {
    const { file, text } = loadFixture("true-positive-01-env-secret-to-response.ts");
    const before = rule.analyze(makeContext(file, text));
    expect(before.length).toBeGreaterThan(0);

    const mutated = text.replace(
      "res.json({ config: token });",
      "const safe = redact(token);\n  res.json({ config: safe });",
    );
    const afterText = "declare function redact(value: string): string;\n" + mutated;
    const after = rule.analyze(makeContext(file, afterText));
    expect(after.length).toBe(0);
  });
});
