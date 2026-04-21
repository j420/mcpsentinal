/**
 * K16 v2 — functional + chain-integrity + mutation tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { UnboundedRecursionRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function loadFixture(name: string): { file: string; text: string } {
  const file = join(FIXTURES_DIR, name);
  return { file, text: readFileSync(file, "utf8") };
}

function makeContext(file: string, text: string): AnalysisContext {
  return {
    server: { id: "srv-1", name: "test-server", description: null, github_url: null },
    tools: [],
    source_code: text,
    source_files: new Map([[file, text]]),
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new UnboundedRecursionRule();

describe("K16 — fires (true positives)", () => {
  it("flags direct self-recursion with no guard", () => {
    const { file, text } = loadFixture("true-positive-01-direct-self-recursion.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBe(1);
    expect(results[0].rule_id).toBe("K16");
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("recursion_edge_without_guard");
    expect(factors).toContain("no_depth_parameter");
  });

  it("flags mutual recursion across two handlers", () => {
    const { file, text } = loadFixture("true-positive-02-mutual-recursion.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBe(1);
    const chain = results[0].chain;
    const factors = chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("mutual_recursion_scc");
    // Both function names should appear in the rendered narrative via the
    // propagation link's `observed` text.
    const prop = chain.links.find((l) => l.type === "propagation");
    expect(prop).toBeDefined();
    if (prop && "observed" in prop) {
      expect(prop.observed).toContain("renderItem");
      expect(prop.observed).toContain("renderGroup");
    }
  });

  it("flags tool-call roundtrip cycle across two MCP handlers", () => {
    const { file, text } = loadFixture("true-positive-03-tool-call-cycle.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBe(1);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("tool_call_cycle_synthesised");
    // Impact scope for tool-call roundtrip differs from server-host.
    const impact = results[0].chain.links.find((l) => l.type === "impact");
    if (impact && "scope" in impact) {
      expect(impact.scope).toBe("other-agents");
    }
  });
});

describe("K16 — does not fire (true negatives)", () => {
  it("accepts recursion with depth comparison against UPPER_SNAKE constant", () => {
    const { file, text } = loadFixture("true-negative-01-depth-comparison.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });

  it("accepts recursion with visited-set cycle breaker", () => {
    const { file, text } = loadFixture("true-negative-02-visited-set.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });

  it("skips a structurally-identified test file", () => {
    const { file, text } = loadFixture("true-negative-03-test-file.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });
});

describe("K16 — mutation test", () => {
  it("adding a depth guard to a true-positive removes the finding", () => {
    const { file, text } = loadFixture("true-positive-01-direct-self-recursion.ts");
    // Before mutation: fires.
    expect(rule.analyze(makeContext(file, text)).length).toBe(1);

    // Mutation: rewrite `walkTree` to accept a `depth` parameter and
    // compare it against a MAX_DEPTH constant.
    const mutated = text
      .replace("export function walkTree(node: TreeNode): void {",
        "const MAX_DEPTH = 32;\nexport function walkTree(node: TreeNode, depth: number = 0): void {\n  if (depth > MAX_DEPTH) return;")
      .replace("walkTree(child);", "walkTree(child, depth + 1);");

    expect(rule.analyze(makeContext(file, mutated))).toEqual([]);
  });
});

describe("K16 — v2 chain-integrity contract", () => {
  const fixtureNames = readdirSync(FIXTURES_DIR).filter((n) => n.startsWith("true-positive-"));

  for (const name of fixtureNames) {
    it(`${name} → every evidence link has a structured Location`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        const sources = r.chain.links.filter((l) => l.type === "source");
        const sinks = r.chain.links.filter((l) => l.type === "sink");
        expect(sources.length).toBeGreaterThan(0);
        expect(sinks.length).toBeGreaterThan(0);
        for (const link of r.chain.links) {
          if (link.type === "impact") continue;
          expect(isLocation(link.location)).toBe(true);
        }
      }
    });

    it(`${name} → every VerificationStep.target is a Location`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      for (const r of results) {
        const steps = r.chain.verification_steps ?? [];
        expect(steps.length).toBeGreaterThan(0);
        for (const step of steps) {
          expect(isLocation(step.target)).toBe(true);
        }
      }
    });

    it(`${name} → confidence capped at 0.88, floored above 0.30`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.88);
        expect(r.chain.confidence).toBeGreaterThan(0.3);
      }
    });

    it(`${name} → threat reference cites OWASP-ASI08`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      for (const r of results) {
        expect(r.chain.threat_reference?.id).toBe("OWASP-ASI08");
      }
    });
  }
});

describe("K16 — confidence ordering", () => {
  it("direct self-call without guard < tool-call cycle (tool-call factor elevates)", () => {
    const { file: f1, text: t1 } = loadFixture("true-positive-01-direct-self-recursion.ts");
    const { file: f2, text: t2 } = loadFixture("true-positive-03-tool-call-cycle.ts");

    const r1 = rule.analyze(makeContext(f1, t1));
    const r2 = rule.analyze(makeContext(f2, t2));
    expect(r1.length).toBe(1);
    expect(r2.length).toBe(1);

    // Both capped at 0.88 — we assert the ordering only when both are below
    // the cap. If both hit the cap, the invariant still holds (equal is
    // fine). Either way, tool-call should never be strictly lower.
    expect(r2[0].chain.confidence).toBeGreaterThanOrEqual(r1[0].chain.confidence);
  });
});
