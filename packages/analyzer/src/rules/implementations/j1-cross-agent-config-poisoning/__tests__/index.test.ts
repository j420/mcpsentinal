/**
 * J1 v2 — functional + chain-integrity tests.
 *
 * Every fixture under ../__fixtures__/ is loaded as a source file into a
 * synthetic AnalysisContext and handed to the rule. We assert:
 *   - TP fixtures produce at least one finding whose chain names the
 *     correct victim agent config suffix;
 *   - TN fixtures produce zero findings;
 *   - every link carries a structured Location (not a prose string);
 *   - every VerificationStep.target is a Location;
 *   - confidence is in the charter range (0.30, 0.90];
 *   - the threat reference is CVE-2025-53773;
 *   - CHARTER edge-case factors fire on the correct fixtures.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { CrossAgentConfigPoisoningRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

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

function loadFixture(name: string): { file: string; text: string } {
  const file = join(FIXTURES_DIR, name);
  return { file, text: readFileSync(file, "utf8") };
}

const rule = new CrossAgentConfigPoisoningRule();

describe("J1 — Cross-Agent Configuration Poisoning (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags a write to ~/.claude/settings.local.json (CVE-2025-53773 primitive)", () => {
      const { file, text } = loadFixture("true-positive-01-write-claude-settings.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        expect(r.rule_id).toBe("J1");
        expect(r.severity).toBe("critical");
      }
      const factors = results.flatMap((r) => r.chain.confidence_factors.map((f) => f.factor));
      expect(factors).toContain("agent_config_target_identified");
    });

    it("flags a write to .cursor/mcp.json assembled from process.env (dynamic_path factor)", () => {
      const { file, text } = loadFixture("true-positive-02-cursor-mcp-json.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const factors = results.flatMap((r) => r.chain.confidence_factors.map((f) => f.factor));
      expect(factors).toContain("dynamic_path_assembly");
    });

    it("flags stealth append to .vscode/settings.json (append_mode_stealth factor)", () => {
      const { file, text } = loadFixture("true-positive-03-appendfile-stealth.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const factors = results.flatMap((r) => r.chain.confidence_factors.map((f) => f.factor));
      expect(factors).toContain("append_mode_stealth");
    });
  });

  describe("does not fire (true negatives)", () => {
    it("ignores a read-only inspection of an agent config", () => {
      const { file, text } = loadFixture("true-negative-01-read-only.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("ignores a write to the server's own namespace", () => {
      const { file, text } = loadFixture("true-negative-02-own-namespace.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });
  });

  describe("chain integrity — v2 contract", () => {
    const tps = readdirSync(FIXTURES_DIR).filter((n) => n.startsWith("true-positive-"));
    for (const name of tps) {
      it(`${name} → every link has a structured Location`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        expect(results.length).toBeGreaterThan(0);
        for (const r of results) {
          const sourceLinks = r.chain.links.filter((l) => l.type === "source");
          const sinkLinks = r.chain.links.filter((l) => l.type === "sink");
          expect(sourceLinks.length).toBeGreaterThan(0);
          expect(sinkLinks.length).toBeGreaterThan(0);
          for (const link of r.chain.links) {
            if (link.type === "impact") continue;
            expect(
              isLocation(link.location),
              `${name} ${link.type} link must be a structured Location`,
            ).toBe(true);
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

      it(`${name} → confidence in charter range (0.30, 0.90]`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.9);
          expect(r.chain.confidence).toBeGreaterThan(0.3);
        }
      });

      it(`${name} → cites CVE-2025-53773 as the primary threat reference`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("CVE-2025-53773");
        }
      });
    }
  });
});
