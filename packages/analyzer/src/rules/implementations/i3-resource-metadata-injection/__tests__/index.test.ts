/**
 * I3 — Resource Metadata Injection: tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ResourceMetadataInjectionRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";
import type { EvidenceChain } from "../../../../evidence.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "__fixtures__");

const rule = new ResourceMetadataInjectionRule();

function loadFixture(name: string): AnalysisContext {
  const parsed = JSON.parse(readFileSync(join(FIX, name), "utf8")) as {
    resources: Array<{
      uri: string;
      name: string;
      description: string | null;
      mimeType: string | null;
    }>;
  };
  return {
    server: { id: "i3-t", name: "i3-test-server", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    resources: parsed.resources,
  };
}

describe("I3 — fires (true positives)", () => {
  it("flags role-override in resource description", () => {
    const r = rule.analyze(loadFixture("true-positive-01-role-override.json"));
    expect(r.length).toBe(1);
    expect(r[0].rule_id).toBe("I3");
    expect(r[0].severity).toBe("critical");
  });
  it("flags LLM delimiter in resource name", () => {
    const r = rule.analyze(loadFixture("true-positive-02-delimiter.json"));
    expect(r.length).toBe(1);
  });
  it("flags action-directive + role-override combination", () => {
    const r = rule.analyze(loadFixture("true-positive-03-action-directive.json"));
    expect(r.length).toBe(1);
    expect(
      r[0].chain.confidence_factors.map((f) => f.factor),
    ).toContain("injection_phrase_matched");
  });
});

describe("I3 — does not fire (true negatives)", () => {
  it("does NOT flag benign documentation description", () => {
    const r = rule.analyze(loadFixture("true-negative-01-benign-docs.json"));
    expect(r.length).toBe(0);
  });
  it("does NOT flag a search endpoint", () => {
    const r = rule.analyze(loadFixture("true-negative-02-search-tool.json"));
    expect(r.length).toBe(0);
  });
  it("does NOT fire when context has no resources", () => {
    const ctx: AnalysisContext = {
      server: { id: "i3-e", name: "empty", description: null, github_url: null },
      tools: [],
      source_code: null,
      dependencies: [],
      connection_metadata: null,
    };
    expect(rule.analyze(ctx).length).toBe(0);
  });
});

describe("I3 — evidence integrity", () => {
  it("every link location and VerificationStep target is structured Location", () => {
    const r = rule.analyze(loadFixture("true-positive-01-role-override.json"));
    const chain: EvidenceChain = r[0].chain;
    for (const link of chain.links) {
      if (link.type === "impact") continue;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(isLocation((link as any).location)).toBe(true);
    }
    for (const step of chain.verification_steps ?? []) {
      expect(isLocation(step.target)).toBe(true);
    }
  });

  it("confidence cap 0.85", () => {
    for (const fix of [
      "true-positive-01-role-override.json",
      "true-positive-02-delimiter.json",
      "true-positive-03-action-directive.json",
    ]) {
      const r = rule.analyze(loadFixture(fix));
      for (const res of r) {
        expect(res.chain.confidence).toBeLessThanOrEqual(0.85);
      }
    }
  });
});
