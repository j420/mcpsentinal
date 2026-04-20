/**
 * K6 v2 — functional + chain-integrity tests.
 *
 * Fires/doesn't-fire assertions on every fixture, plus unit tests on the
 * scope classifier and the full v2 contract: structured Location on every
 * evidence link, Location on every VerificationStep.target, confidence in
 * [0.30, 0.92], threat reference cites ISO 27001 A.5.15 or OWASP ASI03.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { BroadOAuthScopesRule } from "../index.js";
import { classifyScope } from "../gather-ast.js";
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

const rule = new BroadOAuthScopesRule();

describe("K6 — scope classifier (unit)", () => {
  it("classifies exact wildcard, admin, and broad-prefixed tokens", () => {
    expect(classifyScope("*")?.severity).toBe("wildcard");
    expect(classifyScope("admin")?.severity).toBe("admin");
    expect(classifyScope("Admin")?.severity).toBe("admin");
    expect(classifyScope("ROOT")?.severity).toBe("admin");
    expect(classifyScope("read:all")?.severity).toBe("broad");
    expect(classifyScope("write:all")?.severity).toBe("broad");
  });

  it("uses structural suffix split for colon/dot admin segments", () => {
    expect(classifyScope("admin:org")?.severity).toBe("admin");
    expect(classifyScope("bigquery.admin")?.severity).toBe("admin");
    expect(classifyScope("billing:superuser")?.severity).toBe("admin");
  });

  it("uses structural suffix split for colon wildcard segments", () => {
    expect(classifyScope("repo:*")?.severity).toBe("wildcard");
    expect(classifyScope("user.*")?.severity).toBe("wildcard");
  });

  it("does not false-positive on admin-as-substring", () => {
    expect(classifyScope("admin_panel_read")).toBeNull();
    expect(classifyScope("read:admin_dashboard")).toBeNull();
    expect(classifyScope("administrative_data")).toBeNull();
  });

  it("does not false-positive on least-privilege scopes", () => {
    expect(classifyScope("read:user")).toBeNull();
    expect(classifyScope("profile")).toBeNull();
    expect(classifyScope("openid")).toBeNull();
    expect(classifyScope("repo:status")).toBeNull();
  });

  it("returns null on empty/whitespace", () => {
    expect(classifyScope("")).toBeNull();
    expect(classifyScope("   ")).toBeNull();
  });
});

describe("K6 — fires (true positives)", () => {
  it("flags a literal wildcard scope", () => {
    const { file, text } = loadFixture("true-positive-01-wildcard-scope-string.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("broad_scope_wildcard");
  });

  it("flags an array with admin-suffix + broad-prefixed entries", () => {
    const { file, text } = loadFixture("true-positive-02-admin-scope-array.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    // Worst severity is admin (admin:org suffix trumps read:all broad).
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("broad_scope_admin");
    expect(factors).toContain("multiple_broad_entries");
  });

  it("flags a user-controlled scope (req.body.scope)", () => {
    const { file, text } = loadFixture("true-positive-03-user-controlled-scope.ts");
    const results = rule.analyze(makeContext(file, text));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("user_controlled_scope");
    expect(results[0].chain.threat_reference?.id).toBe("OWASP-ASI03");
  });
});

describe("K6 — does not fire (true negatives)", () => {
  it("skips a least-privilege scope declaration", () => {
    const { file, text } = loadFixture("true-negative-01-least-privilege.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });

  it("skips ambiguous `permissions` outside an OAuth context", () => {
    const { file, text } = loadFixture("true-negative-02-ambiguous-permissions-non-oauth.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });

  it("skips a structurally-identified test file even with wildcard scope", () => {
    const { file, text } = loadFixture("true-negative-03-structural-test-file.ts");
    expect(rule.analyze(makeContext(file, text))).toEqual([]);
  });
});

describe("K6 — v2 chain-integrity contract", () => {
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
          expect(
            isLocation(link.location),
            `${name} ${link.type} link location must be a Location, got ${JSON.stringify(link.location)}`,
          ).toBe(true);
        }
      }
    });

    it(`${name} → every VerificationStep.target is a structured Location`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      for (const r of results) {
        const steps = r.chain.verification_steps ?? [];
        expect(steps.length).toBeGreaterThan(0);
        for (const step of steps) {
          expect(
            isLocation(step.target),
            `${name} step ${step.step_type} target must be a Location`,
          ).toBe(true);
        }
      }
    });

    it(`${name} → confidence capped at 0.92, floored above 0.30`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.92);
        expect(r.chain.confidence).toBeGreaterThan(0.3);
      }
    });

    it(`${name} → threat reference cites ISO-27001-A.5.15 or OWASP-ASI03`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(makeContext(file, text));
      for (const r of results) {
        const id = r.chain.threat_reference?.id ?? "";
        expect(["ISO-27001-A.5.15", "OWASP-ASI03"]).toContain(id);
      }
    });
  }
});
