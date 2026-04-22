/**
 * P2 v2 — functional + chain-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DangerousCapabilitiesRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function makeContext(path: string, text: string): AnalysisContext {
  return {
    server: { id: "srv-1", name: "test-server", description: null, github_url: null },
    tools: [],
    source_code: text,
    source_files: new Map([[path, text]]),
    dependencies: [],
    connection_metadata: null,
  };
}

function loadFixture(name: string): { file: string; text: string } {
  const file = join(FIXTURES_DIR, name);
  return { file, text: readFileSync(file, "utf8") };
}

const rule = new DangerousCapabilitiesRule();

describe("P2 — Dangerous Container Capabilities (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags privileged: true (lethal edge #3)", () => {
      const { file, text } = loadFixture("true-positive-01-privileged.yaml");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].rule_id).toBe("P2");
      const sink = results[0].chain.links.find((l) => l.type === "sink");
      expect(sink && sink.type === "sink" && sink.observed.toLowerCase()).toContain("privileged");
    });

    it("flags sys_admin even when paired with drop ALL (lethal edge #2)", () => {
      const { file, text } = loadFixture("true-positive-02-drop-all-plus-add.yaml");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const anyDropAllFactor = results.some((r) =>
        r.chain.confidence_factors.some(
          (f) =>
            f.factor === "drop_all_companion" &&
            f.rationale.toLowerCase().includes("still applies"),
        ),
      );
      expect(anyDropAllFactor).toBe(true);
    });

    it("flags hostPID / hostIPC sharing (lethal edge #4)", () => {
      const { file, text } = loadFixture("true-positive-03-hostpid.yaml");
      const results = rule.analyze(makeContext(file, text));
      const hostPID = results.some((r) => {
        const sink = r.chain.links.find((l) => l.type === "sink");
        return (
          sink && sink.type === "sink" && sink.observed.toLowerCase().includes("hostpid")
        );
      });
      const hostIPC = results.some((r) => {
        const sink = r.chain.links.find((l) => l.type === "sink");
        return (
          sink && sink.type === "sink" && sink.observed.toLowerCase().includes("hostipc")
        );
      });
      expect(hostPID).toBe(true);
      expect(hostIPC).toBe(true);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("accepts cap_drop: ALL + NET_BIND_SERVICE add only", () => {
      const { file, text } = loadFixture("true-negative-01-drop-all-only.yaml");
      const results = rule.analyze(makeContext(file, text));
      // No dangerous capability should trigger — NET_BIND_SERVICE is not in the list.
      expect(results).toEqual([]);
    });

    it("does not fire on a compose file with no securityContext", () => {
      const { file, text } = loadFixture("true-negative-02-no-sec-context.yaml");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });
  });

  describe("chain integrity — v2 contract", () => {
    const all = readdirSync(FIXTURES_DIR).filter((n) => n.startsWith("true-positive-"));
    for (const name of all) {
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
            expect(isLocation(link.location)).toBe(true);
          }
        }
      });

      it(`${name} → VerificationStep targets are Locations`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          for (const step of r.chain.verification_steps ?? []) {
            expect(isLocation(step.target)).toBe(true);
          }
        }
      });

      it(`${name} → confidence within [0.30, 0.85]`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.85);
          expect(r.chain.confidence).toBeGreaterThan(0.3);
        }
      });
    }
  });
});
