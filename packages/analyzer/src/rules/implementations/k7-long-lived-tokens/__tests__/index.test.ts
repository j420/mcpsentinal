/**
 * K7 v2 — functional + chain-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { LongLivedTokensRule } from "../index.js";
import { parseDurationString } from "../gather-ast.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function loadFixture(name: string): { file: string; text: string } {
  const file = join(FIXTURES_DIR, name);
  return { file, text: readFileSync(file, "utf8") };
}

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

const rule = new LongLivedTokensRule();

describe("K7 — duration parser (unit)", () => {
  it("parses bare seconds", () => {
    expect(parseDurationString("86400")).toBe(86400);
    expect(parseDurationString("0")).toBe(0);
    expect(parseDurationString("31536000")).toBe(31536000);
  });

  it("parses unit-suffixed durations", () => {
    expect(parseDurationString("60s")).toBe(60);
    expect(parseDurationString("1m")).toBe(60);
    expect(parseDurationString("1h")).toBe(3600);
    expect(parseDurationString("1d")).toBe(86400);
    expect(parseDurationString("1w")).toBe(604800);
    expect(parseDurationString("1y")).toBe(31536000);
  });

  it("divides ms suffix by 1000", () => {
    expect(parseDurationString("86400000ms")).toBe(86400);
    expect(parseDurationString("1000ms")).toBe(1);
  });

  it("returns null for unparseable values", () => {
    expect(parseDurationString("")).toBeNull();
    expect(parseDurationString("forever")).toBeNull();
    expect(parseDurationString("abc")).toBeNull();
  });
});

describe("K7 — fires (true positives)", () => {
  it("flags jwt.sign without expiresIn", () => {
    const { file, text } = loadFixture("true-positive-01-jwt-sign-no-expiry.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("no_expiry_on_token_call");
  });

  it("flags expiresIn: '365d' as excessive", () => {
    const { file, text } = loadFixture("true-positive-02-excessive-365d.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("excessive_access_token_lifetime");
  });

  it("flags ignoreExpiration: true as disabled-expiry", () => {
    const { file, text } = loadFixture("true-positive-03-disabled-ignore-expiration.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("explicitly_disabled_expiry");
  });
});

describe("K7 — does not fire (true negatives)", () => {
  it("accepts a 1-hour access token", () => {
    const { file, text } = loadFixture("true-negative-01-short-lifetime.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });

  it("accepts a 30-day refresh token under refresh context", () => {
    const { file, text } = loadFixture("true-negative-02-refresh-30d.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });

  it("parses `ms` suffix correctly and does not over-flag a 24h-in-ms value", () => {
    const { file, text } = loadFixture("true-negative-03-ms-units.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });

  it("skips a structurally-identified test file", () => {
    const { file, text } = loadFixture("true-negative-04-test-file.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });
});

describe("K7 — v2 chain-integrity contract", () => {
  const fixtureNames = readdirSync(FIXTURES_DIR).filter((n) => n.startsWith("true-positive-"));

  for (const name of fixtureNames) {
    it(`${name} → every evidence link has a structured Location`, () => {
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

    it(`${name} → confidence capped at 0.90, floored above 0.30`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.9);
        expect(r.chain.confidence).toBeGreaterThan(0.3);
      }
    });

    it(`${name} → threat reference cites ISO-27001-A.8.24`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      for (const r of results) {
        expect(r.chain.threat_reference?.id).toBe("ISO-27001-A.8.24");
      }
    });
  }
});
