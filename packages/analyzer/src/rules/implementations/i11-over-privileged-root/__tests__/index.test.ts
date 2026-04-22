import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { OverPrivilegedRootRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "__fixtures__");

const rule = new OverPrivilegedRootRule();

function loadFixture(name: string): AnalysisContext {
  const parsed = JSON.parse(readFileSync(join(FIX, name), "utf8")) as {
    roots: Array<{ uri: string; name: string | null }>;
  };
  return {
    server: { id: "i11-t", name: "i11", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    roots: parsed.roots,
  };
}

describe("I11 — fires", () => {
  it("flags /etc root", () => {
    const r = rule.analyze(loadFixture("true-positive-01-etc.json"));
    expect(r.length).toBe(1);
    expect(r[0].severity).toBe("high");
  });
  it("flags ~/.ssh root", () => {
    const r = rule.analyze(loadFixture("true-positive-02-ssh.json"));
    expect(r.length).toBe(1);
  });
  it("flags file:/// root", () => {
    const r = rule.analyze(loadFixture("true-positive-03-filesystem-root.json"));
    expect(r.length).toBe(1);
  });
});

describe("I11 — does not fire", () => {
  it("narrow project root", () => {
    const r = rule.analyze(loadFixture("true-negative-01-narrow-project.json"));
    expect(r.length).toBe(0);
  });
  it("app-data directory", () => {
    const r = rule.analyze(loadFixture("true-negative-02-app-dir.json"));
    expect(r.length).toBe(0);
  });
});

describe("I11 — evidence integrity", () => {
  it("structured Locations everywhere", () => {
    const r = rule.analyze(loadFixture("true-positive-01-etc.json"));
    const chain = r[0].chain;
    for (const link of chain.links) {
      if (link.type === "impact") continue;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(isLocation((link as any).location)).toBe(true);
    }
    for (const step of chain.verification_steps ?? []) {
      expect(isLocation(step.target)).toBe(true);
    }
  });

  it("confidence cap 0.90", () => {
    const r = rule.analyze(loadFixture("true-positive-01-etc.json"));
    expect(r[0].chain.confidence).toBeLessThanOrEqual(0.9);
  });
});
