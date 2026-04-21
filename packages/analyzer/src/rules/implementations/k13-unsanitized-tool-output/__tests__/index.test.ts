import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { K13UnsanitizedToolOutputRule } from "../index.js";
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

const rule = new K13UnsanitizedToolOutputRule();

describe("K13 — fires (true positives)", () => {
  it("flags fetch → return without sanitizer", () => {
    const { file, text } = loadFixture("true-positive-01-fetch-to-return.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("K13");
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("external_source_network_fetch");
    expect(factors).toContain("no_sanitizer_on_returned_value");
  });

  it("flags readFileSync → res.send without sanitizer", () => {
    const { file, text } = loadFixture("true-positive-02-file-to-response-call.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("external_source_file_read");
  });

  it("flags handler parameter with external-content name returned raw", () => {
    const { file, text } = loadFixture("true-positive-03-handler-param-unscrubbed.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("external_source_handler_param");
  });
});

describe("K13 — does not fire (true negatives)", () => {
  it("accepts DOMPurify.sanitize applied to the returned identifier", () => {
    const { file, text } = loadFixture("true-negative-01-sanitizer-applied.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });

  it("skips a structurally-identified test file", () => {
    const { file, text } = loadFixture("true-negative-02-test-file.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });
});

describe("K13 — evidence integrity contract", () => {
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
  }
});

describe("K13 — confidence & ordering", () => {
  it("network-fetch source confidence ≥ handler-param source confidence", () => {
    const { file: f1, text: t1 } = loadFixture("true-positive-01-fetch-to-return.ts");
    const { file: f2, text: t2 } = loadFixture("true-positive-03-handler-param-unscrubbed.ts");
    const r1 = rule.analyze(makeContext(f1, t1));
    const r2 = rule.analyze(makeContext(f2, t2));
    expect(r1[0].chain.confidence).toBeGreaterThanOrEqual(r2[0].chain.confidence);
  });

  it("confidence capped at 0.90", () => {
    const fixtures = readdirSync(FIXTURES_DIR).filter((n) => n.startsWith("true-positive-"));
    for (const name of fixtures) {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.90);
      }
    }
  });

  it("threat reference cites CoSAI-MCP-T4", () => {
    const { file, text } = loadFixture("true-positive-01-fetch-to-return.ts");
    const results = rule.analyze(makeContext(file, text));
    for (const r of results) expect(r.chain.threat_reference?.id).toBe("CoSAI-MCP-T4");
  });
});

describe("K13 — mutation test", () => {
  it("TP-01 flips to benign when a sanitize() call is added on the returned identifier", () => {
    const { file, text } = loadFixture("true-positive-01-fetch-to-return.ts");
    const before = rule.analyze(makeContext(file, text));
    expect(before.length).toBeGreaterThan(0);

    const mutated = text.replace(
      "return html;",
      "const safe = sanitize(html);\n  return safe;",
    );
    const after = rule.analyze(makeContext(file, mutated));
    expect(after.length).toBe(0);
  });
});
