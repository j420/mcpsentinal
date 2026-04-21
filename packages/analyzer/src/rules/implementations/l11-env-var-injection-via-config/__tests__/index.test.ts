/**
 * L11 v2 — structural env-block tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { EnvVarInjectionViaConfigRule } from "../index.js";
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

const rule = new EnvVarInjectionViaConfigRule();

describe("L11 — Environment Variable Injection via MCP Config (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags LD_PRELOAD (library-hijack)", () => {
      const { file, text } = loadFixture("true-positive-01-ld-preload.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        expect(r.rule_id).toBe("L11");
        expect(r.severity).toBe("critical");
      }
    });

    it("flags NODE_OPTIONS (runtime-injection)", () => {
      const { file, text } = loadFixture("true-positive-02-node-options.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
    });

    it("flags ANTHROPIC_API_URL + HTTPS_PROXY (api-endpoint + proxy-mitm)", () => {
      const { file, text } = loadFixture("true-positive-03-api-redirect.ts");
      const results = rule.analyze(makeContext(file, text));
      // Expect two findings — one per risky key.
      expect(results.length).toBe(2);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("ignores a safe-only env block", () => {
      const { file, text } = loadFixture("true-negative-01-safe-env.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("ignores an env block outside an mcpServers literal", () => {
      const { file, text } = loadFixture("true-negative-02-non-mcp-env-block.ts");
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

      it(`${name} → confidence in (0.30, 0.85]`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.85);
          expect(r.chain.confidence).toBeGreaterThan(0.3);
        }
      });

      it(`${name} → cites CVE-2026-21852 as the threat reference`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("CVE-2026-21852");
        }
      });
    }
  });
});
