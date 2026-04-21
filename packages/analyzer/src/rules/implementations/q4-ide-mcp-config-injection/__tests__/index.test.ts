/**
 * Q4 v2 — structural IDE-trust-boundary tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { IdeMcpConfigInjectionRule } from "../index.js";
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

const rule = new IdeMcpConfigInjectionRule();

describe("Q4 — IDE MCP Configuration Injection (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags write to .cursor/mcp.json (CVE-2025-54135 CurXecute)", () => {
      const { file, text } = loadFixture("true-positive-01-cursor-mcp-write.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const cves = results.map((r) => r.chain.threat_reference?.id);
      expect(cves).toContain("CVE-2025-54135");
    });

    it("flags enableAllProjectMcpServers + cfg.autoApprove = true", () => {
      const { file, text } = loadFixture("true-positive-02-auto-approve-flag.ts");
      const results = rule.analyze(makeContext(file, text));
      // Two primitives — the object literal and the assignment.
      expect(results.length).toBe(2);
    });

    it("flags case-variant filename (CVE-2025-59944)", () => {
      const { file, text } = loadFixture("true-positive-03-case-variant.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const cves = results.map((r) => r.chain.threat_reference?.id);
      expect(cves).toContain("CVE-2025-59944");
    });
  });

  describe("does not fire (true negatives)", () => {
    it("ignores a read-only inspection of .cursor/mcp.json", () => {
      const { file, text } = loadFixture("true-negative-01-read-ide-config.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("ignores auto-approve flags explicitly set to false", () => {
      const { file, text } = loadFixture("true-negative-02-auto-approve-false.ts");
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
          for (const step of r.chain.verification_steps ?? []) {
            expect(isLocation(step.target)).toBe(true);
          }
        }
      });

      it(`${name} → confidence in (0.30, 0.88]`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.88);
          expect(r.chain.confidence).toBeGreaterThan(0.3);
        }
      });
    }
  });
});
