#!/usr/bin/env tsx
/**
 * Rule Baseline Updater — Phase 0, Chunk 0.3
 *
 * Regenerates `docs/census/regex-baseline.json` from the current state of
 * `packages/analyzer/src/rules/implementations/`. The file drives the
 * no-static-patterns ratchet enforced by `packages/analyzer/__tests__/no-static-patterns.test.ts`.
 *
 * Run this script:
 *   - when a migration chunk (Phase 1) reduces regex counts in a file
 *     and you want the new, lower counts to be enforced as the floor;
 *   - when a new detector file is added that has ZERO static patterns
 *     (clean files don't need a baseline entry, but running this script
 *      prevents the guard from flagging the file as "untracked new");
 *   - NEVER to silence an increase — the guard must reject regressions.
 *     If a legitimate increase is needed (extremely rare), edit the JSON
 *     manually in the same PR and explain in the commit message.
 *
 * Usage:
 *   pnpm rule:baseline
 */

import { readFileSync, readdirSync, statSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, relative, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as ts from "typescript";

/** Recursively list TypeScript source files under a directory, skipping fixtures and tests. */
function walkTsFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) {
      if (name === "__fixtures__" || name === "__tests__" || name === "data") continue;
      walkTsFiles(full, out);
    } else if (st.isFile() && name.endsWith(".ts") && !name.endsWith(".test.ts")) {
      out.push(full);
    }
  }
  return out;
}

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");
const RULES_ROOT = join(
  REPO_ROOT,
  "packages",
  "analyzer",
  "src",
  "rules",
  "implementations",
);
const BASELINE_PATH = join(REPO_ROOT, "docs", "census", "regex-baseline.json");
const MAX_STRING_ARRAY_LITERAL = 5;

interface FileCounts {
  regex_literals: number;
  new_regexp_calls: number;
  string_arrays_over_5: number;
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

function main(): void {
  if (!existsSync(RULES_ROOT)) {
    process.stderr.write(`rule-baseline: rules root not found at ${RULES_ROOT}\n`);
    process.exit(1);
  }
  const files: Record<string, FileCounts> = {};
  for (const full of walkTsFiles(RULES_ROOT)) {
    files[relative(REPO_ROOT, full)] = countStaticPatterns(full);
  }

  const totalRegex = Object.values(files).reduce((n, c) => n + c.regex_literals, 0);
  const totalRegExpCalls = Object.values(files).reduce((n, c) => n + c.new_regexp_calls, 0);
  const totalArrays = Object.values(files).reduce((n, c) => n + c.string_arrays_over_5, 0);

  mkdirSync(dirname(BASELINE_PATH), { recursive: true });
  writeFileSync(
    BASELINE_PATH,
    JSON.stringify(
      {
        version: 1,
        generated_at: new Date().toISOString(),
        notes:
          "Phase 0, Chunk 0.3 regex baseline for packages/analyzer/src/rules/implementations/. " +
          "The analyzer no-static-patterns guard fails CI if any file exceeds the counts " +
          "recorded here. Phase 1's per-rule migrations reduce the baseline file-by-file " +
          "toward zero. Regenerate with `pnpm rule:baseline`.",
        files,
      },
      null,
      2,
    ),
  );
  process.stdout.write(
    `rule-baseline: wrote ${Object.keys(files).length} files, ` +
      `${totalRegex} regex literals, ${totalRegExpCalls} new RegExp calls, ` +
      `${totalArrays} string-arrays > ${MAX_STRING_ARRAY_LITERAL}. ` +
      `→ ${relative(REPO_ROOT, BASELINE_PATH)}\n`,
  );
}

main();
