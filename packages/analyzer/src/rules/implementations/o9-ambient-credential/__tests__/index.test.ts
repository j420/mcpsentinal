/**
 * O9 v2 unit tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { AmbientCredentialRule } from "../index.js";
import { gatherO9 } from "../gather.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation, type Location } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function loadFixture(name: string): AnalysisContext {
  const file = join(FIXTURES_DIR, name);
  const text = readFileSync(file, "utf8");
  return {
    server: { id: "o9-test", name: "o9-test", description: null, github_url: null },
    tools: [],
    source_code: text,
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new AmbientCredentialRule();

describe("O9 — True Positives", () => {
  it("TP-01 literal ~/.aws/credentials path fires", () => {
    const ctx = loadFixture("true-positive-01-aws-credentials-literal.ts");
    const r = rule.analyze(ctx);
    expect(r.length).toBeGreaterThanOrEqual(1);
    expect(r[0].severity).toBe("critical");
    const sites = gatherO9(ctx).sites;
    expect(sites.some((s) => s.kind === "literal-path")).toBe(true);
  });

  it("TP-02 path.join(homedir(), '.ssh', 'id_rsa') fires", () => {
    const ctx = loadFixture("true-positive-02-path-join-ssh.ts");
    const r = rule.analyze(ctx);
    expect(r.length).toBeGreaterThanOrEqual(1);
    const sites = gatherO9(ctx).sites;
    expect(sites.some((s) => s.kind === "path-join")).toBe(true);
  });

  it("TP-03 env-var indirection GOOGLE_APPLICATION_CREDENTIALS fires", () => {
    const ctx = loadFixture("true-positive-03-env-var-indirection.ts");
    const r = rule.analyze(ctx);
    expect(r.length).toBeGreaterThanOrEqual(1);
    const sites = gatherO9(ctx).sites;
    expect(sites.some((s) => s.kind === "env-var-indirection")).toBe(true);
  });
});

describe("O9 — True Negatives", () => {
  it("TN-01 server-scoped config read → 0 findings", () => {
    expect(rule.analyze(loadFixture("true-negative-01-server-scoped-config.ts")).length).toBe(0);
  });

  it("TN-02 unrelated env var → 0 findings", () => {
    expect(rule.analyze(loadFixture("true-negative-02-unrelated-env-var.ts")).length).toBe(0);
  });
});

describe("O9 — Chain integrity", () => {
  it("every chain link carries a structured source Location", () => {
    const ctx = loadFixture("true-positive-01-aws-credentials-literal.ts");
    const r = rule.analyze(ctx);
    for (const link of r[0].chain.links) {
      if (link.type === "impact") continue;
      expect(isLocation(link.location)).toBe(true);
      if (isLocation(link.location)) {
        expect((link.location as Location).kind).toBe("source");
      }
    }
    for (const step of r[0].chain.verification_steps ?? []) {
      expect(isLocation(step.target)).toBe(true);
    }
  });

  it("confidence is capped at 0.85", () => {
    const ctx = loadFixture("true-positive-02-path-join-ssh.ts");
    const r = rule.analyze(ctx);
    expect(r[0].chain.confidence).toBeLessThanOrEqual(0.85);
  });

  it("chain includes source + propagation + sink + impact", () => {
    const r = rule.analyze(loadFixture("true-positive-01-aws-credentials-literal.ts"));
    const types = new Set(r[0].chain.links.map((l) => l.type));
    expect(types.has("source")).toBe(true);
    expect(types.has("propagation")).toBe(true);
    expect(types.has("sink")).toBe(true);
    expect(types.has("impact")).toBe(true);
  });

  it("returns [] when source_code is null", () => {
    expect(
      rule.analyze({
        server: { id: "e", name: "e", description: null, github_url: null },
        tools: [],
        source_code: null,
        dependencies: [],
        connection_metadata: null,
      }).length,
    ).toBe(0);
  });
});
