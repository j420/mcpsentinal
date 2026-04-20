/**
 * K4 v2 — functional + chain-integrity tests.
 *
 * Two test surfaces:
 *
 *   1. Source-code surface — each fixture under ../__fixtures__/ is a
 *      stand-alone .ts file. True-positive fixtures must produce ≥1
 *      finding; true-negative fixtures must produce 0 findings.
 *
 *   2. Tool-schema surface — short inline tool declarations built as
 *      AnalysisContext tool entries. The rule's classification and
 *      required-param check are exercised here; source_code is empty.
 *
 * All findings are checked against the v2 contract: structured Location
 * on every evidence link and every VerificationStep.target, confidence
 * in [0.30, 0.92], both a sink link and a source link, and the threat
 * reference present and matching the charter.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { MissingHumanConfirmationRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";
import { classifyName, tokenise } from "../gather.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function loadFixture(name: string): { file: string; text: string } {
  const file = join(FIXTURES_DIR, name);
  return { file, text: readFileSync(file, "utf8") };
}

function sourceContext(file: string, text: string): AnalysisContext {
  return {
    server: { id: "srv-1", name: "test-server", description: null, github_url: null },
    tools: [],
    source_code: text,
    source_files: new Map([[file, text]]),
    dependencies: [],
    connection_metadata: null,
  };
}

interface ToolLike {
  name: string;
  description?: string | null;
  input_schema: Record<string, unknown> | null;
  annotations?: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  } | null;
}

function toolContext(tool: ToolLike): AnalysisContext {
  return {
    server: { id: "srv-1", name: "test-server", description: null, github_url: null },
    tools: [{
      name: tool.name,
      description: tool.description ?? null,
      input_schema: tool.input_schema,
      annotations: tool.annotations ?? null,
    }],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new MissingHumanConfirmationRule();

describe("K4 — tokenisation + classification (unit)", () => {
  it("splits snake_case, camelCase, kebab-case and digit boundaries", () => {
    expect(tokenise("delete_all_users")).toEqual(["delete", "all", "users"]);
    expect(tokenise("deleteAllUsers")).toEqual(["delete", "all", "users"]);
    expect(tokenise("delete-file")).toEqual(["delete", "file"]);
    expect(tokenise("DropDB")).toEqual(["drop", "db"]);
    expect(tokenise("destroyBatch")).toEqual(["destroy", "batch"]);
    expect(tokenise("XMLHttpRequest")).toEqual(["xml", "http", "request"]);
    expect(tokenise("")).toEqual([]);
  });

  it("classifies destructive verbs, bulk markers, soft markers", () => {
    const c = classifyName("purge_all_logs");
    expect(c.destructive?.verb).toBe("purge");
    expect(c.destructive?.klass).toBe("irrevocable");
    expect(c.bulk).toBe(true);
    expect(c.softMarkers).toEqual([]);
  });

  it("detects soft markers without silencing the destructive verb", () => {
    const c = classifyName("soft_delete_user");
    expect(c.destructive?.verb).toBe("delete");
    expect(c.softMarkers).toContain("soft");
  });

  it("returns destructive=null for non-destructive names", () => {
    expect(classifyName("read_file").destructive).toBeNull();
    expect(classifyName("list_users").destructive).toBeNull();
    expect(classifyName("dropdown").destructive).toBeNull(); // dropdown ≠ drop
  });

  it("is not fooled by substring-only matches", () => {
    // `completion` contains no destructive verb token
    expect(classifyName("completion").destructive).toBeNull();
    // `deletion` stays a single token, doesn't match `delete`
    expect(classifyName("deletion").destructive).toBeNull();
  });
});

describe("K4 — source-code surface (fixtures)", () => {
  describe("fires (true positives)", () => {
    it("flags an unguarded db.deleteAll in an Express handler", () => {
      const { file, text } = loadFixture("true-positive-01-unguarded-delete.ts");
      const results = rule.analyze(sourceContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        expect(r.rule_id).toBe("K4");
        expect(r.severity).toBe("high");
      }
    });

    it("flags a bulk irrevocable destroyBatch call", () => {
      const { file, text } = loadFixture("true-positive-02-destroy-batch.ts");
      const results = rule.analyze(sourceContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const factors = results.flatMap((r) => r.chain.confidence_factors.map((f) => f.factor));
      expect(factors).toContain("destructive_verb_irrevocable");
      expect(factors).toContain("bulk_marker_on_call_symbol");
    });

    it("flags a soft-delete call but records the soft marker factor", () => {
      const { file, text } = loadFixture("true-positive-03-soft-delete-still-fires.ts");
      const results = rule.analyze(sourceContext(file, text));
      expect(results.length).toBeGreaterThan(0);
      const factors = results.flatMap((r) => r.chain.confidence_factors.map((f) => f.factor));
      expect(factors).toContain("soft_marker_reduces_severity");
    });
  });

  describe("does not fire (true negatives)", () => {
    it("recognises a confirm()-guarded IfStatement as a mitigation", () => {
      const { file, text } = loadFixture("true-negative-01-guarded-by-confirm-call.ts");
      expect(rule.analyze(sourceContext(file, text))).toEqual([]);
    });

    it("recognises an `if (force)` flag guard", () => {
      const { file, text } = loadFixture("true-negative-02-force-flag-guard.ts");
      expect(rule.analyze(sourceContext(file, text))).toEqual([]);
    });

    it("skips a structurally-identified test file", () => {
      const { file, text } = loadFixture("true-negative-03-structural-test-file.ts");
      expect(rule.analyze(sourceContext(file, text))).toEqual([]);
    });

    it("recognises a preceding-sibling await confirm() as a forward-flow guard", () => {
      const { file, text } = loadFixture("true-negative-04-preceding-sibling-confirmation.ts");
      expect(rule.analyze(sourceContext(file, text))).toEqual([]);
    });
  });
});

describe("K4 — tool-schema surface (inline)", () => {
  describe("fires when schema lacks a REQUIRED confirmation", () => {
    it("flags delete_file with no confirmation parameter", () => {
      const ctx = toolContext({
        name: "delete_file",
        description: "Delete a file from the filesystem",
        input_schema: { type: "object", properties: { path: { type: "string" } } },
      });
      const results = rule.analyze(ctx);
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].rule_id).toBe("K4");
    });

    it("flags drop_database with irrevocability language in description", () => {
      const ctx = toolContext({
        name: "drop_database",
        description: "Drop an entire database. Cannot be undone.",
        input_schema: { type: "object", properties: { db: { type: "string" } } },
      });
      const results = rule.analyze(ctx);
      expect(results.length).toBeGreaterThan(0);
      const factors = results[0].chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("author_acknowledges_irreversibility");
    });

    it("flags an OPTIONAL confirm parameter as insufficient", () => {
      const ctx = toolContext({
        name: "purge_records",
        description: "Purge old records",
        input_schema: {
          type: "object",
          properties: {
            confirm: { type: "boolean" }, // optional, NOT in `required`
            cutoff: { type: "string" },
          },
          required: ["cutoff"],
        },
      });
      const results = rule.analyze(ctx);
      expect(results.length).toBeGreaterThan(0);
    });

    it("records destructiveHint as a PARTIAL mitigation, does not silence", () => {
      const ctx = toolContext({
        name: "wipe_database",
        description: "Permanently wipe the database",
        input_schema: { type: "object", properties: {} },
        annotations: { destructiveHint: true },
      });
      const results = rule.analyze(ctx);
      expect(results.length).toBeGreaterThan(0);
      const mitigations = results[0].chain.links.filter((l) => l.type === "mitigation");
      const hint = mitigations.find((m) => m.type === "mitigation" && m.mitigation_type === "annotation-hint");
      expect(hint).toBeDefined();
      expect(hint && hint.type === "mitigation" && hint.present).toBe(true);
    });
  });

  describe("does not fire when schema carries a REQUIRED confirmation", () => {
    it("delete_file with required confirm: no finding", () => {
      const ctx = toolContext({
        name: "delete_file",
        description: "Delete a file",
        input_schema: {
          type: "object",
          properties: {
            path: { type: "string" },
            confirm: { type: "boolean" },
          },
          required: ["path", "confirm"],
        },
      });
      expect(rule.analyze(ctx).filter((r) => r.rule_id === "K4")).toEqual([]);
    });

    it("delete_file exposing dry_run is treated as mitigation (optional OK)", () => {
      const ctx = toolContext({
        name: "delete_file",
        description: "Delete a file",
        input_schema: {
          type: "object",
          properties: {
            path: { type: "string" },
            dry_run: { type: "boolean" },
          },
        },
      });
      expect(rule.analyze(ctx).filter((r) => r.rule_id === "K4")).toEqual([]);
    });

    it("read_file — no destructive verb, no finding", () => {
      const ctx = toolContext({
        name: "read_file",
        description: "Read a file from disk",
        input_schema: { type: "object", properties: { path: { type: "string" } } },
      });
      expect(rule.analyze(ctx).filter((r) => r.rule_id === "K4")).toEqual([]);
    });
  });
});

describe("K4 — v2 chain-integrity contract", () => {
  const fixtureNames = readdirSync(FIXTURES_DIR).filter((n) => n.startsWith("true-positive-"));

  for (const name of fixtureNames) {
    it(`${name} → every evidence link has a structured Location`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(sourceContext(file, text));
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
      const results = rule.analyze(sourceContext(file, text));
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
      const results = rule.analyze(sourceContext(file, text));
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.92);
        expect(r.chain.confidence).toBeGreaterThan(0.3);
      }
    });

    it(`${name} → threat reference cites Art.14 or ISO 42001 A.9.2`, () => {
      const { file, text } = loadFixture(name);
      const results = rule.analyze(sourceContext(file, text));
      for (const r of results) {
        const id = r.chain.threat_reference?.id ?? "";
        expect(["EU-AI-Act-Art-14", "ISO-42001-A.9.2"]).toContain(id);
      }
    });
  }

  it("tool-schema findings cite EU-AI-Act-Art-14 as primary reference", () => {
    const ctx = toolContext({
      name: "drop_database",
      description: "Drop the database. Cannot be undone.",
      input_schema: { type: "object", properties: { db: { type: "string" } } },
    });
    const results = rule.analyze(ctx);
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].chain.threat_reference?.id).toBe("EU-AI-Act-Art-14");
  });
});
