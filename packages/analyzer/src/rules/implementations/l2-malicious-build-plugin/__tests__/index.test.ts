/**
 * L2 v2 — Malicious Build Plugin Injection: functional + chain-integrity tests.
 *
 * Fixtures are a mix of JSON (package.json) and TypeScript (build
 * configs). They are mounted into the synthetic source_files map at a
 * path that matches their shape.
 *
 * Covers the CHARTER lethal edge cases:
 *   1. Conditional postinstall gated on env var (TP-01 with CURL + bash)
 *   2. Plugin loaded via require(dynamic) (TP-04)
 *   3. devDependency / postinstall hook (TP-01 — dep section irrelevant)
 *   4. Build-plugin hook body calls fetch/writeFile (TP-02)
 *   5. Plugin from URL (TP-03)
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { MaliciousBuildPluginRule } from "../index.js";
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

/**
 * Mount the fixture at a path that matches its shape so the gather
 * function picks it up on path-based heuristics.
 */
function loadFixture(name: string): { file: string; text: string } {
  const text = readFileSync(join(FIXTURES_DIR, name), "utf8");
  let mountedPath: string;
  if (name.endsWith(".json")) {
    mountedPath = "package.json";
  } else if (name.includes("rollup")) {
    mountedPath = "rollup.config.ts";
  } else if (name.includes("vite")) {
    mountedPath = "vite.config.ts";
  } else if (name.includes("webpack")) {
    mountedPath = "webpack.config.ts";
  } else {
    mountedPath = name;
  }
  return { file: mountedPath, text };
}

const rule = new MaliciousBuildPluginRule();

describe("L2 — Malicious Build Plugin Injection (v2)", () => {
  describe("fires (true positives)", () => {
    it("flags a postinstall fetch-and-exec (install-hook family)", () => {
      const { file, text } = loadFixture("true-positive-01-postinstall-fetch.json");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const kinds = results
        .flatMap((r) => r.chain.confidence_factors)
        .filter((f) => f.factor === "install_time_fetch_primitive" && f.adjustment > 0);
      expect(kinds.length).toBeGreaterThan(0);
      expect(results[0].severity).toBe("critical");
    });

    it("flags a Rollup plugin hook that performs network fetch (dangerous-hook-api family)", () => {
      const { file, text } = loadFixture("true-positive-02-rollup-plugin-fetch.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const apiFactors = results
        .flatMap((r) => r.chain.confidence_factors)
        .filter((f) => f.factor === "dangerous_hook_api_call" && f.adjustment > 0);
      expect(apiFactors.length).toBeGreaterThan(0);
    });

    it("flags an HTTPS URL plugin import (plugin-from-url family)", () => {
      const { file, text } = loadFixture("true-positive-03-vite-url-plugin.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const urlFactors = results
        .flatMap((r) => r.chain.confidence_factors)
        .filter((f) => f.factor === "plugin_from_url_source" && f.adjustment >= 0.2);
      expect(urlFactors.length).toBeGreaterThan(0);
    });

    it("flags a dynamic require(var) plugin load (dynamic-plugin-load family)", () => {
      const { file, text } = loadFixture("true-positive-04-webpack-dynamic-load.ts");
      const results = rule.analyze(makeContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const dynamicFactors = results
        .flatMap((r) => r.chain.confidence_factors)
        .filter((f) => f.factor === "plugin_from_url_source" && f.adjustment > 0);
      expect(dynamicFactors.length).toBeGreaterThan(0);
    });
  });

  describe("does not fire (true negatives)", () => {
    it("recognises a legitimate Rollup config (pure plugin hooks, no dangerous API)", () => {
      const { file, text } = loadFixture("true-negative-01-legitimate-rollup.ts");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("recognises a benign package.json (no install hook fetch-and-exec)", () => {
      const { file, text } = loadFixture("true-negative-02-benign-package-json.json");
      expect(rule.analyze(makeContext(file, text))).toEqual([]);
    });

    it("does not fire on an unrelated source file", () => {
      const ctx = makeContext("src/index.ts", "console.log('hello world');");
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

      it(`${name} → confidence within (0.30, 0.85]`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.confidence).toBeLessThanOrEqual(0.85);
          expect(r.chain.confidence).toBeGreaterThan(0.3);
        }
      });

      it(`${name} → cites CVE-2026-27606 as primary threat reference`, () => {
        const { file, text } = loadFixture(name);
        const results = rule.analyze(makeContext(file, text));
        for (const r of results) {
          expect(r.chain.threat_reference?.id).toBe("CVE-2026-27606");
        }
      });
    }
  });
});
