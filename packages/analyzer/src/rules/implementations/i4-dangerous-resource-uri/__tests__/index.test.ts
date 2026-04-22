/**
 * I4 — Dangerous Resource URI: functional + evidence-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DangerousResourceUriRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";
import type {
  SourceLink,
  SinkLink,
  EvidenceChain,
  VerificationStep,
} from "../../../../evidence.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "__fixtures__");

const rule = new DangerousResourceUriRule();

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
    server: { id: "i4-t", name: "i4-test-server", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    resources: parsed.resources,
  };
}

function getLinksOfType<T extends { type: string }>(
  chain: EvidenceChain,
  t: string,
): T[] {
  return chain.links.filter((l) => l.type === t) as T[];
}

describe("I4 — fires (true positives)", () => {
  it("flags file:/// URI targeting /etc/passwd", () => {
    const results = rule.analyze(loadFixture("true-positive-01-file-scheme.json"));
    expect(results.length).toBe(1);
    expect(results[0].rule_id).toBe("I4");
    expect(results[0].severity).toBe("critical");
  });

  it("flags javascript: URI (XSS primitive)", () => {
    const results = rule.analyze(loadFixture("true-positive-02-javascript-scheme.json"));
    expect(results.length).toBe(1);
    const sinks = getLinksOfType<SinkLink>(results[0].chain, "sink");
    expect(sinks[0].sink_type).toBe("code-evaluation");
  });

  it("flags URL-encoded traversal in an otherwise-benign https URI", () => {
    const results = rule.analyze(loadFixture("true-positive-03-traversal.json"));
    expect(results.length).toBe(1);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("dangerous_scheme_confirmed");
  });
});

describe("I4 — does not fire (true negatives)", () => {
  it("does NOT flag a plain https resource", () => {
    const results = rule.analyze(loadFixture("true-negative-01-https-safe.json"));
    expect(results.length).toBe(0);
  });
  it("does NOT flag an mcp:// transport URI", () => {
    const results = rule.analyze(loadFixture("true-negative-02-mcp-transport.json"));
    expect(results.length).toBe(0);
  });
  it("does NOT fire when context has no resources", () => {
    const ctx: AnalysisContext = {
      server: { id: "i4-empty", name: "empty", description: null, github_url: null },
      tools: [],
      source_code: null,
      dependencies: [],
      connection_metadata: null,
    };
    const results = rule.analyze(ctx);
    expect(results.length).toBe(0);
  });
});

describe("I4 — evidence integrity", () => {
  it("every link location and every verification step target is a structured Location", () => {
    const results = rule.analyze(loadFixture("true-positive-01-file-scheme.json"));
    expect(results.length).toBeGreaterThan(0);
    const chain = results[0].chain;
    for (const link of chain.links) {
      if (link.type === "impact") continue;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(isLocation((link as any).location)).toBe(true);
    }
    for (const step of chain.verification_steps ?? []) {
      expect(isLocation(step.target)).toBe(true);
    }
  });

  it("has a source + sink + impact link and a CVE-2025-53109 threat reference", () => {
    const results = rule.analyze(loadFixture("true-positive-01-file-scheme.json"));
    const chain = results[0].chain;
    expect(getLinksOfType<SourceLink>(chain, "source").length).toBeGreaterThanOrEqual(1);
    expect(getLinksOfType<SinkLink>(chain, "sink").length).toBeGreaterThanOrEqual(1);
    expect(chain.threat_reference?.id).toBe("CVE-2025-53109");
  });

  it("emits at least two verification steps whose targets are structured resource Locations", () => {
    const results = rule.analyze(loadFixture("true-positive-01-file-scheme.json"));
    const steps = (results[0].chain.verification_steps ?? []) as VerificationStep[];
    expect(steps.length).toBeGreaterThanOrEqual(2);
    for (const step of steps) {
      expect(isLocation(step.target)).toBe(true);
    }
  });
});

describe("I4 — confidence", () => {
  it("confidence cap 0.92 is never exceeded", () => {
    for (const fix of [
      "true-positive-01-file-scheme.json",
      "true-positive-02-javascript-scheme.json",
      "true-positive-03-traversal.json",
    ]) {
      const results = rule.analyze(loadFixture(fix));
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.92);
        expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
      }
    }
  });
});
