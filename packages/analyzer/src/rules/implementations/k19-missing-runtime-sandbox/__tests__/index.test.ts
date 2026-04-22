/**
 * K19 v2 — functional + chain-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { MissingRuntimeSandboxRule } from "../index.js";
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

const rule = new MissingRuntimeSandboxRule();

describe("K19 — Missing Runtime Sandbox Enforcement (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags privileged: true", () => {
      const { file, text } = loadFixture("true-positive-01-privileged.yaml");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const hits = results.map((r) => r.chain.links.find((l) => l.type === "sink"));
      const privileged = hits.some((s) => s && s.type === "sink" && s.observed.toLowerCase().includes("privileged"));
      expect(privileged).toBe(true);
    });

    it("flags YAML-list capability add (SYS_ADMIN, NET_RAW)", () => {
      const { file, text } = loadFixture("true-positive-02-cap-add-sys-admin.yaml");
      const results = rule.analyze(makeContext(file, text));
      // SYS_ADMIN + NET_RAW = 2 findings.
      expect(results.length).toBeGreaterThanOrEqual(2);
      const observedAll = results.map((r) =>
        r.chain.links.find((l) => l.type === "sink")?.observed.toUpperCase() ?? "",
      );
      expect(observedAll.some((o) => o.includes("SYS_ADMIN"))).toBe(true);
      expect(observedAll.some((o) => o.includes("NET_RAW"))).toBe(true);
    });

    it("flags hostPID: true independently of privileged", () => {
      const { file, text } = loadFixture("true-positive-03-host-pid.yaml");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const categories = results.map((r) => {
        const sink = r.chain.links.find((l) => l.type === "sink");
        return sink && sink.type === "sink" ? sink.observed : "";
      });
      expect(categories.some((c) => c.includes("host-namespace-share"))).toBe(true);
    });

    it("flags explicit seccomp: Unconfined", () => {
      const { file, text } = loadFixture("true-positive-04-seccomp-unconfined.yaml");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const anySeccomp = results.some((r) => {
        const sink = r.chain.links.find((l) => l.type === "sink");
        return sink && sink.type === "sink" && sink.observed.toLowerCase().includes("security-profile-disable");
      });
      expect(anySeccomp).toBe(true);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("accepts CIS Baseline-compliant pod spec", () => {
      const { file, text } = loadFixture("true-negative-01-hardened.yaml");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("does not fire on commented-out disable flags", () => {
      const { file, text } = loadFixture("true-negative-02-comment-line.yaml");
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
            expect(isLocation(link.location), `link ${link.type}`).toBe(true);
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

      it(`${name} → confidence within [0.10, 0.85]`, () => {
        // Lower bound 0.10 because the mitigation link adjusts -0.30
        // when compensating sandbox controls are present in the same file
        // (runAsNonRoot + readOnlyRootFilesystem etc.). The finding is
        // still a real compliance failure — just at reduced confidence.
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.85);
          expect(r.chain.confidence).toBeGreaterThan(0.1);
        }
      });
    }
  });
});
