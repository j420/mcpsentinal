/**
 * K3 v2 — Audit Log Tampering: functional + chain-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { AuditLogTamperingRule } from "../index.js";
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

const rule = new AuditLogTamperingRule();

describe("K3 — Audit Log Tampering (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags read-filter-write round-trip on an audit log", () => {
      const { file, text } = loadFixture("true-positive-01-read-filter-write.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        expect(r.rule_id).toBe("K3");
        expect(r.severity).toBe("critical");
      }
      const factors = results.flatMap((r) => r.chain.confidence_factors.map((f) => f.factor));
      expect(factors).toContain("tampering_operation");
    });

    it("flags a sed -i shell command targeting an audit path", () => {
      const { file, text } = loadFixture("true-positive-02-sed-inplace.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
    });

    it("flags openSync with r+ on an audit path", () => {
      const { file, text } = loadFixture("true-positive-03-rw-mode-open.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
    });

    it("flags utimesSync on an audit path (timestamp forgery)", () => {
      const { file, text } = loadFixture("true-positive-04-timestamp-forgery.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("does not fire on append-only logging", () => {
      const { file, text } = loadFixture("true-negative-01-append-only.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("does not fire on legitimate GDPR PII redaction", () => {
      const { file, text } = loadFixture("true-negative-02-legit-pii-redaction.ts");
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
              `${name} ${link.type} location must be a Location`,
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

      it(`${name} → cites CVE-2024-52798 as primary threat reference`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("CVE-2024-52798");
        }
      });
    }
  });
});
