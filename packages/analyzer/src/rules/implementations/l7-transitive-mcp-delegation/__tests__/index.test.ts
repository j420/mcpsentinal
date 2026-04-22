/**
 * L7 v2 — Transitive MCP Delegation: functional + chain-integrity tests.
 *
 * Fixtures:
 *   TP-01 : dual-sdk-import — server + client SDK imports, no forwarding.
 *   TP-02 : credential-forwarding — proxy passes req.headers.authorization.
 *   TP-03 : transport-only — server imports StdioClientTransport and new's it.
 *   TN-01 : server-only (no client imports).
 *   TN-02 : client-only (no server imports).
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { TransitiveMCPDelegationRule } from "../index.js";
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
  const text = readFileSync(join(FIXTURES_DIR, name), "utf8");
  return { file: `src/${name}`, text };
}

const rule = new TransitiveMCPDelegationRule();

describe("L7 — Transitive MCP Delegation (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags dual-sdk-import (server + client SDK in one file)", () => {
      const { file, text } = loadFixture("true-positive-01-dual-sdk-import.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        expect(r.rule_id).toBe("L7");
        expect(r.severity).toBe("critical");
      }
    });

    it("flags credential-forwarding (req.headers.authorization to upstream)", () => {
      const { file, text } = loadFixture("true-positive-02-credential-forwarding.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const factors = results.flatMap((r) =>
        r.chain.confidence_factors.map((f) => f.factor),
      );
      expect(factors).toContain("credential_forwarding_observed");
    });

    it("flags transport-only import + new <Transport>(...)", () => {
      const { file, text } = loadFixture("true-positive-03-transport-only.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const hasConstruction = results.some((r) =>
        r.chain.confidence_factors.some(
          (f) => f.factor === "client_or_transport_instantiation" && f.adjustment > 0,
        ),
      );
      expect(hasConstruction).toBe(true);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("does not fire on a pure MCP server (no client imports)", () => {
      const { file, text } = loadFixture("true-negative-01-server-only.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("does not fire on a pure MCP client (no server imports)", () => {
      const { file, text } = loadFixture("true-negative-02-client-only.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("does not fire on unrelated source", () => {
      const ctx = makeContext("src/x.ts", "export const x = 1;");
      expect(rule.analyze(ctx)).toEqual([]);
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
          const sources = r.chain.links.filter((l) => l.type === "source");
          const sinks = r.chain.links.filter((l) => l.type === "sink");
          expect(sources.length).toBeGreaterThan(0);
          expect(sinks.length).toBeGreaterThan(0);
          for (const link of r.chain.links) {
            if (link.type === "impact") continue;
            expect(
              isLocation(link.location),
              `${name} ${link.type} location must be a Location — got ${JSON.stringify(link.location)}`,
            ).toBe(true);
          }
        }
      });

      it(`${name} → every VerificationStep.target is a structured Location`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          const steps = r.chain.verification_steps ?? [];
          expect(steps.length).toBeGreaterThanOrEqual(2);
          for (const step of steps) {
            expect(
              isLocation(step.target),
              `${name} step ${step.step_type} target must be a Location — got ${JSON.stringify(step.target)}`,
            ).toBe(true);
          }
        }
      });

      it(`${name} → confidence capped at 0.85, floored above 0.05`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.85);
          expect(r.chain.confidence).toBeGreaterThan(0.05);
        }
      });

      it(`${name} → cites the arXiv "When MCP Servers Attack" paper`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe(
            "arxiv-2509.24272-when-mcp-servers-attack",
          );
        }
      });
    }
  });
});
