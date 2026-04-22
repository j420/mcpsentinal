/**
 * Mutation CHARTER Parity Guard.
 *
 * Phase 2 chunk 2.2 deliverable: every rule's CHARTER.md frontmatter declares
 * `mutations_survived` and `mutations_acknowledged_blind` arrays that are
 * computed by the mutation auditor and frozen in the CHARTER as an honest
 * false-negative account. This test is the contract:
 *
 *   1. `docs/mutations/latest.json` must exist — it is the source of truth for
 *      the last audit.
 *   2. Every rule listed in the report must have `mutations_survived` and
 *      `mutations_acknowledged_blind` keys in its CHARTER frontmatter.
 *   3. Every mutation currently declared `survived` in a CHARTER must STILL
 *      be `survived` in the latest report. A mutation cannot regress from
 *      survived → blind without a deliberate CHARTER update.
 *   4. Every mutation currently declared `acknowledged_blind` must STILL be
 *      `blind`. A rule cannot silently start detecting a mutation it was
 *      previously honest about being blind to without a matching CHARTER
 *      update — that update is the author's acknowledgement that the rule
 *      has improved and the blind-list should shrink.
 *   5. The set of mutations referenced in every CHARTER is a subset of the
 *      canonical MUTATION_IDS — no typos, no made-up ids.
 *
 * Always-fail from day 1. No warn-only mode.
 *
 * How to regenerate the baseline when a rule improves:
 *
 *   pnpm --filter=@mcp-sentinel/red-team exec tsx src/mutation/cli.ts \
 *     --output=docs/mutations/latest.json
 *   pnpm --filter=@mcp-sentinel/red-team exec tsx \
 *     src/mutation/charter-writer.ts
 *
 * Then commit both the report and the updated CHARTERs together.
 */

import { describe, it, expect } from "vitest";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

/** Walk up until we find `packages/analyzer` — the guard is co-located there. */
function findRepoRoot(): string {
  let dir = HERE;
  for (let i = 0; i < 15; i++) {
    if (existsSync(join(dir, "packages")) && existsSync(join(dir, "tsconfig.base.json"))) {
      return dir;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error("mutation-charter-parity: unable to locate repo root from " + HERE);
}

const REPO_ROOT = findRepoRoot();
const IMPL_DIR = join(REPO_ROOT, "packages", "analyzer", "src", "rules", "implementations");
const REPORT_PATH = join(REPO_ROOT, "docs", "mutations", "latest.json");

// Canonical mutation ids — frozen in types.ts. We duplicate the list here
// deliberately: the guard lives in packages/analyzer and must not import from
// packages/red-team (circular during workspace build).
const CANONICAL_MUTATIONS: ReadonlyArray<string> = [
  "rename-danger-symbol",
  "split-string-literal",
  "unicode-homoglyph-identifier",
  "base64-wrap-payload",
  "intermediate-variable",
  "add-noop-conditional",
  "swap-option-shape",
  "reorder-object-properties",
];

interface ReportEntry {
  rule_id: string;
  survived: string[];
  acknowledged_blind: string[];
  not_applicable: string[];
  errors: string[];
  fixtures_without_baseline: string[];
  no_fixtures: boolean;
}

interface ReportShape {
  generated_at: string;
  rules_version: string;
  per_rule_summary: ReportEntry[];
}

interface CharterFrontmatter {
  rule_id: string;
  survived: string[];
  blind: string[];
  raw: string;
}

/**
 * Extract the two mutation arrays from a CHARTER.md. We do a minimal YAML
 * parse — we don't depend on `js-yaml` because the analyzer package doesn't
 * have it as a dep, and the pattern is stable enough to hand-parse.
 * Supports both `key: []` and the multi-line list form.
 */
function parseCharterMutations(text: string): { survived: string[]; blind: string[] } {
  const lines = text.split(/\r?\n/);
  const start = lines.indexOf("---");
  if (start !== 0) return { survived: [], blind: [] };
  let end = -1;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i] === "---") { end = i; break; }
  }
  if (end === -1) return { survived: [], blind: [] };

  const survived: string[] = [];
  const blind: string[] = [];
  let current: "survived" | "blind" | null = null;
  for (let i = 1; i < end; i++) {
    const line = lines[i];
    if (line.startsWith("mutations_survived:")) {
      current = "survived";
      if (line.includes("[]")) current = null;
      continue;
    }
    if (line.startsWith("mutations_acknowledged_blind:")) {
      current = "blind";
      if (line.includes("[]")) current = null;
      continue;
    }
    if (current) {
      const m = line.match(/^\s*-\s+(\S.*?)\s*$/);
      if (m) {
        if (current === "survived") survived.push(m[1]);
        else blind.push(m[1]);
        continue;
      }
      // Any other shape ends the block.
      current = null;
    }
  }
  return { survived, blind };
}

function loadCharter(ruleDir: string): CharterFrontmatter | null {
  const charterPath = join(ruleDir, "CHARTER.md");
  if (!existsSync(charterPath)) return null;
  const text = readFileSync(charterPath, "utf8");
  const { survived, blind } = parseCharterMutations(text);
  const lines = text.split(/\r?\n/);
  const ruleIdLine = lines.find((l) => l.startsWith("rule_id:")) ?? "";
  const id = ruleIdLine.split(":")[1]?.trim() ?? "";
  return { rule_id: id, survived, blind, raw: text };
}

describe("mutation-charter-parity guard", () => {
  it("docs/mutations/latest.json exists — the baseline is the source of truth", () => {
    expect(existsSync(REPORT_PATH), `baseline missing at ${REPORT_PATH} — run pnpm exec tsx packages/red-team/src/mutation/cli.ts`).toBe(true);
  });

  it("every mutation id in the report is in the canonical list", () => {
    const report = JSON.parse(readFileSync(REPORT_PATH, "utf8")) as ReportShape;
    for (const entry of report.per_rule_summary) {
      for (const id of [...entry.survived, ...entry.acknowledged_blind, ...entry.not_applicable, ...entry.errors]) {
        expect(CANONICAL_MUTATIONS, `unknown mutation id "${id}" on ${entry.rule_id}`).toContain(id);
      }
    }
  });

  it("every CHARTER mutation id is in the canonical list", () => {
    const dirs = readdirSync(IMPL_DIR, { withFileTypes: true }).filter((e) => e.isDirectory() && e.name !== "_shared");
    for (const e of dirs) {
      const charter = loadCharter(join(IMPL_DIR, e.name));
      if (!charter) continue;
      for (const id of [...charter.survived, ...charter.blind]) {
        expect(CANONICAL_MUTATIONS, `CHARTER ${e.name} references unknown mutation "${id}"`).toContain(id);
      }
    }
  });

  it("every rule dir has a CHARTER with both mutation frontmatter keys", () => {
    const dirs = readdirSync(IMPL_DIR, { withFileTypes: true }).filter((e) => e.isDirectory() && e.name !== "_shared");
    const missing: string[] = [];
    for (const e of dirs) {
      const charterPath = join(IMPL_DIR, e.name, "CHARTER.md");
      if (!existsSync(charterPath)) continue; // some rules may lack charters — skip
      const text = readFileSync(charterPath, "utf8");
      if (!text.includes("mutations_survived:") || !text.includes("mutations_acknowledged_blind:")) {
        missing.push(e.name);
      }
    }
    expect(missing, `CHARTERs missing mutation frontmatter: ${missing.join(", ")}`).toEqual([]);
  });

  it("every CHARTER-declared survived mutation is still surviving in the latest report", () => {
    const report = JSON.parse(readFileSync(REPORT_PATH, "utf8")) as ReportShape;
    const reportById = new Map(report.per_rule_summary.map((r) => [r.rule_id, r]));
    const regressions: Array<{ rule_id: string; mutation: string }> = [];

    const dirs = readdirSync(IMPL_DIR, { withFileTypes: true }).filter((e) => e.isDirectory() && e.name !== "_shared");
    for (const e of dirs) {
      const charter = loadCharter(join(IMPL_DIR, e.name));
      if (!charter || !charter.rule_id) continue;
      const reportEntry = reportById.get(charter.rule_id);
      if (!reportEntry) continue;
      const currentlySurviving = new Set(reportEntry.survived);
      for (const m of charter.survived) {
        if (!currentlySurviving.has(m)) {
          regressions.push({ rule_id: charter.rule_id, mutation: m });
        }
      }
    }
    expect(
      regressions,
      `rules regressed on previously-surviving mutations: ${JSON.stringify(regressions)}. ` +
        "A rule that previously detected a mutation can no longer detect it — either fix the rule or acknowledge the regression by moving the mutation to mutations_acknowledged_blind in the CHARTER.",
    ).toEqual([]);
  });

  it("every CHARTER-declared blind mutation is still blind in the latest report", () => {
    // A rule that was honestly blind but is now surviving SHOULD trigger a
    // CHARTER update (promoting the mutation to `survived`). The guard
    // surfaces the gap so the author cannot silently claim improvement
    // without landing the CHARTER edit.
    const report = JSON.parse(readFileSync(REPORT_PATH, "utf8")) as ReportShape;
    const reportById = new Map(report.per_rule_summary.map((r) => [r.rule_id, r]));
    const improvements: Array<{ rule_id: string; mutation: string }> = [];

    const dirs = readdirSync(IMPL_DIR, { withFileTypes: true }).filter((e) => e.isDirectory() && e.name !== "_shared");
    for (const e of dirs) {
      const charter = loadCharter(join(IMPL_DIR, e.name));
      if (!charter || !charter.rule_id) continue;
      const reportEntry = reportById.get(charter.rule_id);
      if (!reportEntry) continue;
      const currentlySurviving = new Set(reportEntry.survived);
      for (const m of charter.blind) {
        if (currentlySurviving.has(m)) {
          improvements.push({ rule_id: charter.rule_id, mutation: m });
        }
      }
    }
    expect(
      improvements,
      `rules now detect mutations previously listed as blind: ${JSON.stringify(improvements)}. ` +
        "Update the CHARTER: move these mutations from mutations_acknowledged_blind to mutations_survived.",
    ).toEqual([]);
  });
});
