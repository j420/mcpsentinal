/**
 * L3 v2 — functional + chain-integrity tests.
 *
 * Fixture files are Dockerfiles (not .ts). We load each via readFileSync
 * and hand it to the rule via a synthetic AnalysisContext whose
 * source_files map contains a single "Dockerfile" entry.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DockerfileBaseImageRiskRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function makeContext(_fixtureFileName: string, text: string): AnalysisContext {
  // Always present the fixture under a canonical "Dockerfile" basename so
  // the path-based candidate filter (isDockerfilePath) matches. The fixture's
  // real on-disk name is irrelevant to the rule; only the content matters.
  const dockerfilePath = "Dockerfile";
  return {
    server: { id: "srv-1", name: "test-server", description: null, github_url: null },
    tools: [],
    source_code: text,
    source_files: new Map([[dockerfilePath, text]]),
    dependencies: [],
    connection_metadata: null,
  };
}

function loadFixture(name: string): { file: string; text: string } {
  const file = join(FIXTURES_DIR, name);
  return { file, text: readFileSync(file, "utf8") };
}

const rule = new DockerfileBaseImageRiskRule();

describe("L3 — Dockerfile Base Image Supply Chain Risk (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags a FROM instruction with no tag", () => {
      const { file, text } = loadFixture("true-positive-01-no-tag.Dockerfile");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBe(1);
      expect(results[0].rule_id).toBe("L3");
      expect(results[0].severity).toBe("high");
      const factors = results[0].chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("unpinned_base_image");
    });

    it("flags dev-tag camouflage (`latest-prod`)", () => {
      const { file, text } = loadFixture("true-positive-02-mutable-tag-dev-camouflage.Dockerfile");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBe(1);
      const obs = results[0].chain.links.find((l) => l.type === "source");
      expect(obs).toBeDefined();
      // The observed text should contain "latest-prod".
      if (obs && obs.type === "source") {
        expect(obs.observed.toLowerCase()).toContain("latest-prod");
      }
    });

    it("flags the unpinned builder in a multi-stage build (runtime is pinned)", () => {
      const { file, text } = loadFixture("true-positive-03-multi-stage-unpinned-builder.Dockerfile");
      const results = rule.analyze(makeContext(file, text));
      // Exactly one finding — the builder stage. The runtime stage pins a digest.
      expect(results.length).toBe(1);
      // Mitigation factor must record that SOME digest pin exists in the file.
      const factors = results[0].chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("digest_present_elsewhere_in_dockerfile");
    });

    it("flags an ARG-referenced base image", () => {
      const { file, text } = loadFixture("true-positive-04-arg-reference.Dockerfile");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBe(1);
      const src = results[0].chain.links.find((l) => l.type === "source");
      expect(src).toBeDefined();
      if (src && src.type === "source") {
        expect(src.rationale.toLowerCase()).toContain("arg");
      }
    });
  });

  describe("does not fire (true negatives)", () => {
    it("accepts a fully digest-pinned FROM", () => {
      const { file, text } = loadFixture("true-negative-01-digest-pinned.Dockerfile");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("accepts `scratch` and `--platform=`-flagged pinned FROMs", () => {
      const { file, text } = loadFixture("true-negative-02-scratch.Dockerfile");
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
            expect(
              isLocation(link.location),
              `${name} ${link.type} link location must be a structured Location, got ${JSON.stringify(link.location)}`,
            ).toBe(true);
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
            expect(isLocation(step.target), `${name} step target must be Location`).toBe(true);
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

      it(`${name} → cites AML.T0017 as threat reference`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("AML.T0017");
        }
      });
    }
  });

  describe("charter lethal edge cases", () => {
    it("flag-stripping: --platform does NOT become the image", () => {
      const { file, text } = loadFixture("true-negative-02-scratch.Dockerfile");
      const results = rule.analyze(makeContext(file, text));
      // Every FROM in the fixture is either scratch or digest-pinned with --platform.
      expect(results).toEqual([]);
    });

    it("scratch-exact-match: 'scratch' is allowed, 'scratch-extras' would not be", () => {
      const text = "FROM scratch-extras\nCMD [\"/bin/sh\"]\n";
      const ctx = makeContext("Dockerfile", text);
      const results = rule.analyze(ctx);
      expect(results.length).toBe(1);
    });
  });
});
