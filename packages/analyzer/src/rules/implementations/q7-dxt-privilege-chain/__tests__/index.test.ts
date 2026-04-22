/**
 * Q7 v2 unit tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DxtPrivilegeChainRule } from "../index.js";
import { gatherQ7 } from "../gather.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation, type Location } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function loadFixture(name: string): AnalysisContext {
  const file = join(FIXTURES_DIR, name);
  const text = readFileSync(file, "utf8");
  return {
    server: { id: "q7-test", name: "q7-test", description: null, github_url: null },
    tools: [],
    source_code: text,
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new DxtPrivilegeChainRule();

describe("Q7 — True Positives", () => {
  it("TP-01 autoApprove: true fires", () => {
    const ctx = loadFixture("true-positive-01-auto-approve.ts");
    const r = rule.analyze(ctx);
    expect(r.length).toBeGreaterThanOrEqual(1);
    expect(r[0].severity).toBe("critical");
    const sites = gatherQ7(ctx).sites;
    expect(sites.some((s) => s.kind === "auto-approve-flag")).toBe(true);
  });

  it("TP-02 chrome.runtime.sendNativeMessage fires", () => {
    const ctx = loadFixture("true-positive-02-native-messaging.ts");
    const r = rule.analyze(ctx);
    expect(r.length).toBeGreaterThanOrEqual(1);
    const sites = gatherQ7(ctx).sites;
    expect(sites.some((s) => s.kind === "native-messaging-bridge")).toBe(true);
  });

  it("TP-03 ipcMain.handle fires", () => {
    const ctx = loadFixture("true-positive-03-ipc-handle.ts");
    const r = rule.analyze(ctx);
    expect(r.length).toBeGreaterThanOrEqual(1);
    const sites = gatherQ7(ctx).sites;
    expect(sites.some((s) => s.kind === "ipc-handler")).toBe(true);
  });
});

describe("Q7 — True Negatives", () => {
  it("TN-01 no ingress patterns → 0 findings", () => {
    expect(rule.analyze(loadFixture("true-negative-01-no-ingress.ts")).length).toBe(0);
  });

  it("TN-02 handle() on non-ipcMain receiver → 0 findings", () => {
    expect(rule.analyze(loadFixture("true-negative-02-unrelated-handle.ts")).length).toBe(0);
  });
});

describe("Q7 — Chain integrity", () => {
  it("every chain link carries a structured source Location", () => {
    const ctx = loadFixture("true-positive-01-auto-approve.ts");
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

  it("confidence is capped at 0.82", () => {
    const ctx = loadFixture("true-positive-02-native-messaging.ts");
    const r = rule.analyze(ctx);
    expect(r[0].chain.confidence).toBeLessThanOrEqual(0.82);
  });

  it("chain includes source + propagation + sink + impact", () => {
    const r = rule.analyze(loadFixture("true-positive-01-auto-approve.ts"));
    const types = new Set(r[0].chain.links.map((l) => l.type));
    expect(types.has("source")).toBe(true);
    expect(types.has("propagation")).toBe(true);
    expect(types.has("sink")).toBe(true);
    expect(types.has("impact")).toBe(true);
  });
});
