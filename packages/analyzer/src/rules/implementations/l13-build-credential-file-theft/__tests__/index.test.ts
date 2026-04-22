/**
 * L13 v2 — Build Credential File Theft: functional + chain-integrity tests.
 *
 * Fixtures cover all three finding families:
 *   - TP-01 : read .npmrc → fetch (taint-cred-to-network via taint-rule-kit)
 *   - TP-02 : read .docker/config.json, no immediate network sink
 *             (cred-file-read-direct structural variant)
 *   - TP-03 : Dockerfile COPY .npmrc — dockerfile-copy-cred variant
 *   - TN-01 : no credential-file substring anywhere
 *   - TN-02 : BuildKit --mount=type=secret Dockerfile — RUN line only
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { BuildCredentialFileTheftRule } from "../index.js";
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
  let mountedPath: string;
  if (name.endsWith(".Dockerfile")) {
    mountedPath = "Dockerfile";
  } else {
    mountedPath = `src/${name}`;
  }
  return { file: mountedPath, text };
}

const rule = new BuildCredentialFileTheftRule();

describe("L13 — Build Credential File Theft (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags a .npmrc read → fetch exfil chain (taint-cred-to-network)", () => {
      const { file, text } = loadFixture("true-positive-01-npmrc-to-fetch.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const factors = results
        .flatMap((r) => r.chain.confidence_factors)
        .map((f) => f.factor);
      expect(factors).toContain("cred_file_path_substring");
      expect(results[0].severity).toBe("critical");
    });

    it("flags a .docker/config.json read (cred-file-read-direct variant)", () => {
      const { file, text } = loadFixture("true-positive-02-docker-config-read.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      // The direct-read variant uses credential-exposure sink (not network-send).
      const sinks = results
        .flatMap((r) => r.chain.links)
        .filter((l) => l.type === "sink");
      expect(sinks.length).toBeGreaterThan(0);
    });

    it("flags a Dockerfile COPY .npmrc (dockerfile-copy-cred variant)", () => {
      const { file, text } = loadFixture("true-positive-03-dockerfile-copy.Dockerfile");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      // Dockerfile finding emits a config-kind Location with json_pointer /instructions/<index>.
      const configLocations = results
        .flatMap((r) => r.chain.links)
        .map((l) => l.location)
        .filter(
          (loc): loc is { kind: "config"; file: string; json_pointer: string } =>
            typeof loc === "object" &&
            loc !== null &&
            "kind" in loc &&
            loc.kind === "config",
        );
      expect(configLocations.length).toBeGreaterThan(0);
      for (const loc of configLocations) {
        expect(loc.json_pointer.startsWith("/instructions/")).toBe(true);
      }
    });
  });

  describe("does not fire (true negatives)", () => {
    it("does not fire on a file-read of ordinary user content", () => {
      const { file, text } = loadFixture("true-negative-01-no-cred-file-io.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("does not fire on a Dockerfile that uses BuildKit secret mount (no COPY of .npmrc)", () => {
      const { file, text } = loadFixture("true-negative-02-buildkit-secret.Dockerfile");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("does not fire on an unrelated source", () => {
      const ctx = makeContext("src/x.ts", "export const x = 1;");
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
          const sources = r.chain.links.filter((l) => l.type === "source");
          const sinks = r.chain.links.filter((l) => l.type === "sink");
          expect(sources.length).toBeGreaterThan(0);
          expect(sinks.length).toBeGreaterThan(0);
          for (const link of r.chain.links) {
            if (link.type === "impact") continue;
            expect(
              isLocation(link.location),
              `${name}: ${link.type} location is not a Location — ${JSON.stringify(link.location)}`,
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

      it(`${name} → confidence capped at 0.85`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.85);
          expect(r.chain.confidence).toBeGreaterThan(0.1);
        }
      });

      it(`${name} → cites CVE-2025-55155 as primary threat reference`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("CVE-2025-55155");
        }
      });
    }
  });
});
