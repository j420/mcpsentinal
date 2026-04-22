/**
 * P7 v2 — functional + chain-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { HostFilesystemMountRule } from "../index.js";
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

const rule = new HostFilesystemMountRule();

describe("P7 — Sensitive Host Filesystem Mount (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags full host root mount (hostPath: /)", () => {
      const { file, text } = loadFixture("true-positive-01-root-mount.yaml");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].rule_id).toBe("P7");
      const variant = results[0].chain.confidence_factors.find((f) => f.factor === "host_path_variant");
      expect(variant?.rationale.toLowerCase()).toContain("host-root");
    });

    it("flags /etc mount with :ro (lethal edge #4 — read-only is NOT a mitigation)", () => {
      const { file, text } = loadFixture("true-positive-02-etc-readonly.yaml");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const ro = results[0].chain.confidence_factors.find((f) => f.factor === "readonly_flag_present");
      expect(ro?.rationale.toLowerCase()).toContain("reduces (but does not eliminate)");
    });

    it("flags /var/lib/kubelet mount (lethal edge #5)", () => {
      const { file, text } = loadFixture("true-positive-03-kubelet.yaml");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const kubelet = results.some((r) => {
        const v = r.chain.confidence_factors.find((f) => f.factor === "host_path_variant");
        return v?.rationale.includes("kubelet-credentials");
      });
      expect(kubelet).toBe(true);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("accepts ConfigMap volume type", () => {
      const { file, text } = loadFixture("true-negative-01-configmap.yaml");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("accepts emptyDir scratch volume", () => {
      const { file, text } = loadFixture("true-negative-02-emptydir.yaml");
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
