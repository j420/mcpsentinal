/**
 * L1 v2 — GitHub Actions Tag Poisoning: functional + chain-integrity tests.
 *
 * Every fixture is a workflow YAML. We mount it under
 * `.github/workflows/<name>.yml` in a synthetic source_files map so the
 * rule's structural filter recognises it as a workflow.
 *
 * Assertions cover:
 *   - TP fixtures produce at least one finding;
 *   - TN fixtures produce zero findings;
 *   - every link's location is a structured Location (Location.kind set);
 *   - every VerificationStep.target is a Location;
 *   - the CHARTER's lethal edge cases each have a corresponding test.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { GitHubActionsTagPoisoningRule } from "../index.js";
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
  const mountedPath = `.github/workflows/${name}`;
  return { file: mountedPath, text };
}

const rule = new GitHubActionsTagPoisoningRule();

describe("L1 — GitHub Actions Tag Poisoning (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags a mutable major-version tag (structural-yaml-walk)", () => {
      const { file, text } = loadFixture("true-positive-01-mutable-major-tag.yml");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const families = results
        .flatMap((r) => r.chain.confidence_factors)
        .map((f) => f.factor);
      expect(families).toContain("mutable_tag_reference");
      for (const r of results) {
        expect(r.rule_id).toBe("L1");
        expect(r.severity).toBe("critical");
      }
    });

    it("flags expression-interpolated refs (${{ matrix.x }})", () => {
      const { file, text } = loadFixture("true-positive-02-expression-interpolated.yml");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const pointers = results.map((r) =>
        r.chain.links.find((l) => l.type === "source")?.location,
      );
      const hasExpressionPointer = pointers.some(
        (loc) =>
          typeof loc === "object" &&
          loc !== null &&
          "kind" in loc &&
          loc.kind === "config" &&
          loc.json_pointer.includes("steps/1/uses"),
      );
      expect(hasExpressionPointer).toBe(true);
    });

    it("flags curl|bash pipe-to-shell in a run step", () => {
      const { file, text } = loadFixture("true-positive-03-pipe-to-shell.yml");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const factors = results
        .flatMap((r) => r.chain.confidence_factors)
        .filter((f) => f.factor === "pipe_to_shell_in_run" && f.adjustment > 0);
      expect(factors.length).toBeGreaterThan(0);
    });

    it("flags a nested reusable-workflow call at job-level uses: (post-release tag rewrite scenario)", () => {
      const { file, text } = loadFixture("true-positive-04-reusable-workflow.yml");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const sourceLocation = results[0].chain.links.find((l) => l.type === "source")?.location;
      expect(typeof sourceLocation === "object" && sourceLocation !== null).toBe(true);
      if (
        typeof sourceLocation === "object" &&
        sourceLocation !== null &&
        "kind" in sourceLocation &&
        sourceLocation.kind === "config"
      ) {
        expect(sourceLocation.json_pointer).toContain("/jobs/");
        expect(sourceLocation.json_pointer.endsWith("/uses")).toBe(true);
      }
    });
  });

  describe("does not fire (true negatives)", () => {
    it("recognises a fully SHA-pinned workflow", () => {
      const { file, text } = loadFixture("true-negative-01-sha-pinned.yml");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("does not flag run steps whose pipes are not pipe-to-shell", () => {
      const { file, text } = loadFixture("true-negative-02-harden-runner-safe-run.yml");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("ignores files that are not workflows", () => {
      const ctx = makeContext("src/index.ts", "console.log('not a workflow')");
      expect(rule.analyze(ctx)).toEqual([]);
    });
  });

  describe("chain integrity — v2 contract", () => {
    const tpFixtures = readdirSync(FIXTURES_DIR).filter((n) => n.startsWith("true-positive-"));

    for (const name of tpFixtures) {
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
              `${name}: ${link.type}.location is not a Location — got ${JSON.stringify(link.location)}`,
            ).toBe(true);
          }
        }
      });

      it(`${name} → every VerificationStep.target is a structured Location`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          const steps = r.chain.verification_steps ?? [];
          expect(steps.length).toBeGreaterThanOrEqual(3);
          for (const step of steps) {
            expect(
              isLocation(step.target),
              `${name}: step ${step.step_type} target is not a Location`,
            ).toBe(true);
          }
        }
      });

      it(`${name} → confidence within [0.30, 0.90]`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.9);
          expect(r.chain.confidence).toBeGreaterThan(0.3);
        }
      });

      it(`${name} → cites CVE-2025-30066 as primary threat reference`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("CVE-2025-30066");
        }
      });
    }
  });
});
