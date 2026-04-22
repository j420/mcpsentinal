/**
 * Q15 v2 unit tests — functional + chain-integrity.
 *
 * Edge cases covered (mirroring CHARTER.md lethal_edge_cases):
 *   - TP-01 AgentCard skill → registerTool (card ingestion)
 *   - TP-02 TaskResult parts → callTool (part-policy bypass)
 *   - TP-03 pushNotification → sendToolResult (re-entry)
 *   - TP-04 discoverAgents → registerTool (unverified discovery)
 *   - TP-05 sanitize() present → finding demoted but still emitted
 *   - TN-01 honest-refusal: no A2A surface in source
 *   - TN-02 A2A surface without any MCP sink in same function
 *
 * Chain-integrity assertions per Rule Standard v2.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Q15Rule } from "../index.js";
import { gatherQ15 } from "../gather.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function loadFixture(name: string): AnalysisContext {
  const file = join(FIXTURES_DIR, name);
  const text = readFileSync(file, "utf8");
  return {
    server: { id: "q15-test", name: "q15-test", description: null, github_url: null },
    tools: [],
    source_code: text,
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new Q15Rule();

describe("Q15 — True Positives", () => {
  it("TP-01 AgentCard skills → registerTool fires", () => {
    const ctx = loadFixture("true-positive-01-agent-card-skill-to-tool.ts");
    const results = rule.analyze(ctx);
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0].severity).toBe("high");
    const sites = gatherQ15(ctx).sites;
    expect(sites.some((s) => s.a2aSurfaces.some((h) => h.kind === "agent-card"))).toBe(true);
    expect(sites.some((s) => s.mcpSinks.some((m) => m.sinkName === "registerTool"))).toBe(true);
  });

  it("TP-02 TaskResult parts → callTool fires", () => {
    const ctx = loadFixture("true-positive-02-task-parts-to-tool-input.ts");
    const results = rule.analyze(ctx);
    expect(results.length).toBeGreaterThanOrEqual(1);
    const sites = gatherQ15(ctx).sites;
    expect(sites.some((s) => s.a2aSurfaces.some((h) => h.kind === "part"))).toBe(true);
    expect(sites.some((s) => s.mcpSinks.some((m) => m.sinkName === "callTool"))).toBe(true);
  });

  it("TP-03 pushNotification → sendToolResult fires (re-entry)", () => {
    const ctx = loadFixture("true-positive-03-push-notification-re-entry.ts");
    const results = rule.analyze(ctx);
    expect(results.length).toBeGreaterThanOrEqual(1);
    const sites = gatherQ15(ctx).sites;
    expect(sites.some((s) => s.a2aSurfaces.some((h) => h.kind === "push"))).toBe(true);
    expect(sites.some((s) => s.mcpSinks.some((m) => m.sinkName === "sendToolResult"))).toBe(true);
  });

  it("TP-04 discoverAgents + a2a:// URI → registerTool fires", () => {
    const ctx = loadFixture("true-positive-04-discovery-to-registertool.ts");
    const results = rule.analyze(ctx);
    expect(results.length).toBeGreaterThanOrEqual(1);
    const sites = gatherQ15(ctx).sites;
    expect(sites.some((s) => s.a2aSurfaces.some((h) => h.kind === "discovery" || h.kind === "uri"))).toBe(true);
    // The discovery-or-uri bonus factor should apply.
    const factorNames = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factorNames).toContain("unverified_discovery_or_uri");
  });

  it("TP-05 sanitize() in scope → still fires, demotion factor recorded", () => {
    const ctx = loadFixture("true-positive-05-sanitize-demotes.ts");
    const results = rule.analyze(ctx);
    expect(results.length).toBeGreaterThanOrEqual(1);
    const factorNames = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factorNames).toContain("content_policy_demotes");
    // Demoted confidence should be below an unsanitized TP-01 case.
    const tp1Results = rule.analyze(
      loadFixture("true-positive-01-agent-card-skill-to-tool.ts"),
    );
    expect(results[0].chain.confidence).toBeLessThan(tp1Results[0].chain.confidence);
  });
});

describe("Q15 — True Negatives", () => {
  it("TN-01 honest-refusal: no A2A surface → 0 findings", () => {
    const ctx = loadFixture("true-negative-01-pure-mcp.ts");
    const gathered = gatherQ15(ctx);
    expect(gathered.hasA2aSurface).toBe(false);
    expect(rule.analyze(ctx).length).toBe(0);
  });

  it("TN-02 A2A surface without MCP sink → 0 findings", () => {
    expect(rule.analyze(loadFixture("true-negative-02-a2a-only-no-mcp.ts")).length).toBe(0);
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

describe("Q15 — Chain integrity", () => {
  const TP_NAMES = [
    "true-positive-01-agent-card-skill-to-tool.ts",
    "true-positive-02-task-parts-to-tool-input.ts",
    "true-positive-03-push-notification-re-entry.ts",
    "true-positive-04-discovery-to-registertool.ts",
    "true-positive-05-sanitize-demotes.ts",
  ];

  for (const name of TP_NAMES) {
    it(`${name} → every non-impact link has a structured Location`, () => {
      const results = rule.analyze(loadFixture(name));
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        for (const link of r.chain.links) {
          if (link.type === "impact") continue;
          expect(isLocation(link.location)).toBe(true);
        }
      }
    });

    it(`${name} → every VerificationStep.target is a Location`, () => {
      const results = rule.analyze(loadFixture(name));
      for (const r of results) {
        const steps = r.chain.verification_steps ?? [];
        expect(steps.length).toBeGreaterThan(0);
        for (const step of steps) {
          expect(isLocation(step.target)).toBe(true);
        }
      }
    });

    it(`${name} → confidence capped at 0.78`, () => {
      const results = rule.analyze(loadFixture(name));
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.78);
        expect(r.chain.confidence).toBeGreaterThan(0.1);
      }
    });

    it(`${name} → cites AAIF-Linux-Foundation`, () => {
      const results = rule.analyze(loadFixture(name));
      for (const r of results) {
        expect(r.chain.threat_reference?.id).toBe("AAIF-Linux-Foundation");
      }
    });

    it(`${name} → chain contains source + propagation + sink + impact`, () => {
      const results = rule.analyze(loadFixture(name));
      for (const r of results) {
        const types = new Set(r.chain.links.map((l) => l.type));
        expect(types.has("source")).toBe(true);
        expect(types.has("propagation")).toBe(true);
        expect(types.has("sink")).toBe(true);
        expect(types.has("impact")).toBe(true);
      }
    });
  }
});
