import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { K12ExecutableContentResponseRule } from "../index.js";
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

const rule = new K12ExecutableContentResponseRule();

describe("K12 — fires (true positives)", () => {
  it("flags eval in response-emitting call", () => {
    const { file, text } = loadFixture("true-positive-01-eval-in-response.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("K12");
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("exec_eval_call");
  });

  it("flags <script> tag in returned template literal", () => {
    const { file, text } = loadFixture("true-positive-02-script-tag-in-return.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("exec_script_tag_string");
  });
});

describe("K12 — does not fire (true negatives)", () => {
  it("recognises DOMPurify.sanitize in enclosing scope", () => {
    const { file, text } = loadFixture("true-negative-01-sanitized-output.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });

  it("accepts a plain-text JSON response", () => {
    const { file, text } = loadFixture("true-negative-02-plain-text-response.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });

  it("skips a structurally-identified test file", () => {
    const { file, text } = loadFixture("true-negative-03-test-file.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });
});

describe("K12 — v2 chain-integrity contract", () => {
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

    it(`${name} → threat reference cites CoSAI-MCP-T4`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      for (const r of results) expect(r.chain.threat_reference?.id).toBe("CoSAI-MCP-T4");
    });
  }
});
