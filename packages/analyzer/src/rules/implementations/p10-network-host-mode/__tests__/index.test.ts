/**
 * P10 v2 — functional + chain-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { HostNetworkModeRule } from "../index.js";
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

const rule = new HostNetworkModeRule();

describe("P10 — Host Network Mode (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags docker-compose network_mode: host", () => {
      const { file, text } = loadFixture("true-positive-01-compose-host.yaml");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].rule_id).toBe("P10");
    });

    it("flags Kubernetes hostNetwork: true", () => {
      const { file, text } = loadFixture("true-positive-02-k8s-hostnetwork.yaml");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const src = results[0].chain.links.find((l) => l.type === "source");
      expect(src && src.type === "source" && src.observed.toLowerCase()).toContain("hostnetwork");
    });

    it("flags --net=host (CLI alias form, lethal edge case #1)", () => {
      const { file, text } = loadFixture("true-positive-03-cli-net-host.sh");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const variants = results.map((r) => {
        const factor = r.chain.confidence_factors.find((f) => f.factor === "variant_form");
        return factor?.rationale ?? "";
      });
      expect(variants.some((v) => v.includes("docker-cli-net-host"))).toBe(true);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("accepts bridge network", () => {
      const { file, text } = loadFixture("true-negative-01-bridge.yaml");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("does not fire on hostNetwork: false + commented-out example", () => {
      const { file, text } = loadFixture("true-negative-02-hostnetwork-false.yaml");
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

      it(`${name} → confidence within [0.30, 0.80]`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.8);
          expect(r.chain.confidence).toBeGreaterThan(0.3);
        }
      });

      it(`${name} → cites CVE-2019-5736`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("CVE-2019-5736");
        }
      });
    }
  });
});
