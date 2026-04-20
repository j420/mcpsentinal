/**
 * No-Static-Patterns Guard (Analyzer Mirror)
 *
 * Phase 0, Chunk 0.3. Mirrors `packages/compliance-agents/__tests__/no-static-patterns.test.ts`
 * so the same AST-level ban that protects `packages/compliance-agents/src/rules/`
 * also tracks `packages/analyzer/src/rules/implementations/`.
 *
 * Semantics differ from the compliance-agents version:
 *
 *   - The compliance-agents guard is STRICT from day one (zero tolerance) —
 *     that package was authored under the no-static-patterns rule from scratch.
 *
 *   - The analyzer is in the middle of a Phase 1 migration. It starts with
 *     853 regex literals across 37 detector files (see docs/census/latest.md).
 *     Applying strict enforcement today would block the repo.
 *
 *   - Instead, this guard enforces a MONOTONIC RATCHET against a committed
 *     baseline file (`docs/census/regex-baseline.json`):
 *
 *       new regex literal in a file → fail CI
 *       new `new RegExp(...)` call  → fail CI
 *       new string-literal array >5 → fail CI
 *       removing an existing one     → info; run `pnpm rule:baseline` to ratchet down
 *
 * Phase 0 makes this test **warn-only** — it reports, but never fails. The
 * mode flips to enforcing at the end of Phase 1, Chunk 1.27, when every
 * detector file has been migrated or its baseline agreed. To flip early,
 * set ANALYZER_STATIC_GUARD_STRICT=true in the environment.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, existsSync, writeFileSync, mkdirSync } from "node:fs";
import { join, relative, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as ts from "typescript";

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(HERE, "..");
const REPO_ROOT = resolve(PACKAGE_ROOT, "..", "..");
const RULES_ROOT = join(PACKAGE_ROOT, "src", "rules", "implementations");
const BASELINE_PATH = join(REPO_ROOT, "docs", "census", "regex-baseline.json");

const MAX_STRING_ARRAY_LITERAL = 5;
const STRICT = process.env.ANALYZER_STATIC_GUARD_STRICT === "true";

interface FileCounts {
  regex_literals: number;
  new_regexp_calls: number;
  string_arrays_over_5: number;
}

interface Baseline {
  version: 1;
  generated_at: string;
  notes: string;
  files: Record<string, FileCounts>;
}

function listRuleFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    if (!name.endsWith(".ts") || name.endsWith(".test.ts")) continue;
    out.push(join(dir, name));
  }
  return out;
}

function countStaticPatterns(file: string): FileCounts {
  const text = readFileSync(file, "utf8");
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.ES2022, true);
  const counts: FileCounts = {
    regex_literals: 0,
    new_regexp_calls: 0,
    string_arrays_over_5: 0,
  };
  function visit(node: ts.Node): void {
    if (ts.isRegularExpressionLiteral(node)) counts.regex_literals++;
    if (
      (ts.isNewExpression(node) || ts.isCallExpression(node)) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === "RegExp"
    ) {
      counts.new_regexp_calls++;
    }
    if (ts.isArrayLiteralExpression(node) && node.elements.length > MAX_STRING_ARRAY_LITERAL) {
      const allStrings = node.elements.every(
        (e) => ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e),
      );
      if (allStrings) counts.string_arrays_over_5++;
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  return counts;
}

function snapshotCurrent(): Record<string, FileCounts> {
  const out: Record<string, FileCounts> = {};
  for (const full of listRuleFiles(RULES_ROOT)) {
    const rel = relative(REPO_ROOT, full);
    out[rel] = countStaticPatterns(full);
  }
  return out;
}

function writeBaseline(files: Record<string, FileCounts>): void {
  const baseline: Baseline = {
    version: 1,
    generated_at: new Date().toISOString(),
    notes:
      "Phase 0, Chunk 0.3 regex baseline for packages/analyzer/src/rules/implementations/. " +
      "The analyzer no-static-patterns guard fails CI if any file exceeds the counts " +
      "recorded here. Phase 1's per-rule migrations reduce the baseline file-by-file " +
      "toward zero. Regenerate with `pnpm rule:baseline`.",
    files,
  };
  mkdirSync(dirname(BASELINE_PATH), { recursive: true });
  writeFileSync(BASELINE_PATH, JSON.stringify(baseline, null, 2));
}

function loadBaseline(): Baseline | null {
  if (!existsSync(BASELINE_PATH)) return null;
  try {
    const parsed = JSON.parse(readFileSync(BASELINE_PATH, "utf8")) as Baseline;
    if (parsed?.version !== 1 || typeof parsed.files !== "object") return null;
    return parsed;
  } catch {
    return null;
  }
}

interface Violation {
  file: string;
  metric: keyof FileCounts;
  current: number;
  baseline: number;
}

function diff(current: Record<string, FileCounts>, baseline: Baseline): {
  regressions: Violation[];
  improvements: Violation[];
  untracked_new_files: string[];
} {
  const regressions: Violation[] = [];
  const improvements: Violation[] = [];
  const untracked: string[] = [];

  for (const [file, now] of Object.entries(current)) {
    const base = baseline.files[file];
    if (!base) {
      // New file — treat a new file with ANY regex as a regression.
      if (now.regex_literals > 0 || now.new_regexp_calls > 0 || now.string_arrays_over_5 > 0) {
        untracked.push(file);
        if (now.regex_literals > 0) {
          regressions.push({ file, metric: "regex_literals", current: now.regex_literals, baseline: 0 });
        }
        if (now.new_regexp_calls > 0) {
          regressions.push({ file, metric: "new_regexp_calls", current: now.new_regexp_calls, baseline: 0 });
        }
        if (now.string_arrays_over_5 > 0) {
          regressions.push({ file, metric: "string_arrays_over_5", current: now.string_arrays_over_5, baseline: 0 });
        }
      }
      continue;
    }
    for (const k of Object.keys(now) as Array<keyof FileCounts>) {
      if (now[k] > base[k]) {
        regressions.push({ file, metric: k, current: now[k], baseline: base[k] });
      } else if (now[k] < base[k]) {
        improvements.push({ file, metric: k, current: now[k], baseline: base[k] });
      }
    }
  }
  return { regressions, improvements, untracked_new_files: untracked };
}

describe("no-static-patterns guard (analyzer, warn-only in Phase 0)", () => {
  it("baseline file exists (or is written on first run)", () => {
    const current = snapshotCurrent();
    const baseline = loadBaseline();
    if (!baseline) {
      // First run — write the baseline so the next CI invocation can compare.
      writeBaseline(current);
      console.warn(
        `no-static-patterns: baseline not found — wrote a fresh snapshot to ${relative(REPO_ROOT, BASELINE_PATH)}. ` +
          `Commit this file; subsequent runs will fail on regressions.`,
      );
    }
    expect(Object.keys(current).length).toBeGreaterThan(0);
  });

  it("no file exceeds its recorded regex / RegExp / string-array-over-5 baseline", () => {
    const current = snapshotCurrent();
    const baseline = loadBaseline();
    // If no baseline yet, the previous test wrote one — nothing to compare.
    if (!baseline) return;

    const { regressions, improvements, untracked_new_files } = diff(current, baseline);

    if (improvements.length > 0) {
      const lines = improvements.map(
        (v) => `  ${v.file} — ${v.metric}: ${v.baseline} → ${v.current}`,
      );
      console.info(
        `no-static-patterns: ${improvements.length} improvement(s) detected. Run \`pnpm rule:baseline\` to ratchet down.\n${lines.join("\n")}`,
      );
    }

    if (regressions.length === 0) return;

    const lines = regressions.map(
      (v) => `  ${v.file} — ${v.metric}: baseline ${v.baseline}, now ${v.current}`,
    );
    const untrackedLines = untracked_new_files.map((f) => `  ${f}`);
    const msg =
      `no-static-patterns: ${regressions.length} regression(s) detected:\n${lines.join("\n")}` +
      (untracked_new_files.length > 0
        ? `\nuntracked new files (baseline is implicit 0):\n${untrackedLines.join("\n")}`
        : "") +
      `\nOptions:\n` +
      `  (a) Remove the new regex / RegExp call / string-array > ${MAX_STRING_ARRAY_LITERAL} and use AST / capability-graph analysis instead.\n` +
      `  (b) If you are INTENTIONALLY raising a baseline (very rare — requires review), update ${relative(REPO_ROOT, BASELINE_PATH)} in the same PR.`;

    if (STRICT) {
      throw new Error(msg);
    } else {
      console.warn(`[warn-only — ANALYZER_STATIC_GUARD_STRICT=true to enforce]\n${msg}`);
    }
  });
});
