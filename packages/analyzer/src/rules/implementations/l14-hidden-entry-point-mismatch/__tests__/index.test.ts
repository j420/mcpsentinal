/**
 * L14 v2 — stub rule tests.
 *
 * L14's analyze() must always return `[]`. The parent L5 rule is the
 * source of truth for L14 findings; re-running detection here would
 * double-count. These tests guarantee the stub cannot silently start
 * producing findings.
 */

import { describe, it, expect } from "vitest";
import { HiddenEntryPointMismatchStub } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";

function emptyContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "test-server", description: null, github_url: null },
    tools: [],
    source_code: null,
    source_files: null,
    dependencies: [],
    connection_metadata: null,
  };
}

function richContext(): AnalysisContext {
  const pkg = JSON.stringify({
    name: "shadowing-example",
    version: "1.0.0",
    bin: { git: "./bin/git.js", "mcp-server": "./.hidden.js" },
    exports: {
      ".": { import: "./esm/index.js", require: "./cjs/.payload.cjs" },
    },
  });
  return {
    server: { id: "srv-1", name: "test-server", description: null, github_url: null },
    tools: [],
    source_code: pkg,
    source_files: new Map([["package.json", pkg]]),
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new HiddenEntryPointMismatchStub();

describe("L14 — Hidden Entry Point Mismatch (stub companion to L5)", () => {
  it("returns [] for an empty context", () => {
    expect(rule.analyze(emptyContext())).toEqual([]);
  });

  it("returns [] even for a context that would fire L5", () => {
    // This is the load-bearing assertion. If L14 ever starts producing
    // findings on its own, every manifest with a shadowed bin entry
    // double-counts (L5 emits L14 → stub also emits L14).
    expect(rule.analyze(richContext())).toEqual([]);
  });

  it("declares a stub technique and source_code requirement", () => {
    expect(rule.technique).toBe("stub");
    expect(rule.requires.source_code).toBe(true);
  });

  it("registers the correct rule id and name", () => {
    expect(rule.id).toBe("L14");
    expect(rule.name).toContain("Hidden Entry Point");
  });
});
