/**
 * K8 v2 — Cross-Boundary Credential Sharing: functional + chain tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { CrossBoundaryCredentialSharingRule } from "../index.js";
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
  return { file: `src/${name}`, text: readFileSync(join(FIXTURES_DIR, name), "utf8") };
}

const rule = new CrossBoundaryCredentialSharingRule();

describe("K8 — Cross-Boundary Credential Sharing (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags bearer header forwarded to a different origin", () => {
      const { file, text } = loadFixture("true-positive-01-bearer-header-forward.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        expect(r.rule_id).toBe("K8");
        expect(r.severity).toBe("critical");
      }
      const sinks = results.flatMap((r) => r.chain.links.filter((l) => l.type === "sink"));
      expect(sinks.some((s) => s.type === "sink" && s.sink_type === "network-send")).toBe(true);
    });

    it("flags an api_key written to Redis", () => {
      const { file, text } = loadFixture("true-positive-02-redis-shared-store.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const sinks = results.flatMap((r) => r.chain.links.filter((l) => l.type === "sink"));
      expect(sinks.some((s) => s.type === "sink" && s.sink_type === "config-modification")).toBe(true);
    });

    it("flags execSync with a bearer token in argv", () => {
      const { file, text } = loadFixture("true-positive-03-exec-with-token.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const sinks = results.flatMap((r) => r.chain.links.filter((l) => l.type === "sink"));
      expect(sinks.some((s) => s.type === "sink" && s.sink_type === "command-execution")).toBe(true);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("does not fire when RFC 8693 Token Exchange delegation is used", () => {
      const { file, text } = loadFixture("true-negative-01-token-exchange.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("does not fire on credential-free HTTP POST", () => {
      const { file, text } = loadFixture("true-negative-02-same-trust-boundary.ts");
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
          const sources = r.chain.links.filter((l) => l.type === "source");
          const sinks = r.chain.links.filter((l) => l.type === "sink");
          expect(sources.length).toBeGreaterThan(0);
          expect(sinks.length).toBeGreaterThan(0);
          for (const link of r.chain.links) {
            if (link.type === "impact") continue;
            expect(isLocation(link.location)).toBe(true);
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
            expect(isLocation(step.target)).toBe(true);
          }
        }
      });

      it(`${name} → confidence capped at 0.85`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.85);
          expect(r.chain.confidence).toBeGreaterThan(0.1);
        }
      });

      it(`${name} → cites OWASP-ASI03 as primary threat reference`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("OWASP-ASI03");
        }
      });
    }
  });
});
