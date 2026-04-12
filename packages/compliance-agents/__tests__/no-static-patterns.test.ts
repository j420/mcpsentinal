/**
 * No-Static-Patterns Guard
 *
 * Mechanically enforces the rule-authoring contract: every file under
 * `src/rules/` MUST be free of regex literals, `new RegExp(...)` calls,
 * and string-literal arrays longer than 5 entries.
 *
 * The dual-persona authoring protocol relies on this — without it, a future
 * contributor could quietly slip a regex back in and destroy the "no static,
 * no regex" guarantee the package depends on.
 *
 * The guard uses the TypeScript compiler API for AST scanning so the check
 * is precise: comments, doc strings, and identifiers are ignored.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import * as ts from "typescript";

const PACKAGE_ROOT = new URL("..", import.meta.url).pathname;
const RULES_ROOT = join(PACKAGE_ROOT, "src", "rules");
const MAX_STRING_ARRAY_LITERAL = 5;

function listTsFiles(dir: string): string[] {
  const out: string[] = [];
  const entries = readdirSync(dir);
  for (const name of entries) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) {
      out.push(...listTsFiles(full));
    } else if (name.endsWith(".ts") && !name.endsWith(".test.ts")) {
      out.push(full);
    }
  }
  return out;
}

interface Violation {
  file: string;
  line: number;
  reason: string;
}

function scanFile(file: string): Violation[] {
  const text = readFileSync(file, "utf8");
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.ES2022, true);
  const violations: Violation[] = [];

  function lineOf(pos: number): number {
    return sf.getLineAndCharacterOfPosition(pos).line + 1;
  }

  function visit(node: ts.Node): void {
    // 1. Regex literals: /foo/
    if (ts.isRegularExpressionLiteral(node)) {
      violations.push({
        file,
        line: lineOf(node.getStart(sf)),
        reason: `regex literal: ${node.getText(sf).slice(0, 40)}`,
      });
    }

    // 2. new RegExp(...) and RegExp(...)
    if (ts.isNewExpression(node) || ts.isCallExpression(node)) {
      const expr = node.expression;
      if (ts.isIdentifier(expr) && expr.text === "RegExp") {
        violations.push({
          file,
          line: lineOf(node.getStart(sf)),
          reason: "RegExp constructor",
        });
      }
    }

    // 3. String-literal arrays longer than MAX_STRING_ARRAY_LITERAL
    if (ts.isArrayLiteralExpression(node)) {
      const allStringLiterals =
        node.elements.length > 0 &&
        node.elements.every(
          (e) => ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e),
        );
      if (allStringLiterals && node.elements.length > MAX_STRING_ARRAY_LITERAL) {
        violations.push({
          file,
          line: lineOf(node.getStart(sf)),
          reason: `string-literal array of length ${node.elements.length} (max ${MAX_STRING_ARRAY_LITERAL})`,
        });
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(sf);
  return violations;
}

describe("no-static-patterns guard", () => {
  it("scans every file under src/rules/", () => {
    const files = listTsFiles(RULES_ROOT);
    expect(files.length).toBeGreaterThan(0);
  });

  it("forbids regex literals, RegExp constructors, and long string-literal arrays in src/rules/", () => {
    const files = listTsFiles(RULES_ROOT);
    const allViolations: Violation[] = [];
    for (const f of files) {
      allViolations.push(...scanFile(f));
    }

    if (allViolations.length > 0) {
      const lines = allViolations.map((v) => {
        const rel = relative(PACKAGE_ROOT, v.file);
        return `  ${rel}:${v.line} — ${v.reason}`;
      });
      throw new Error(
        `no-static-patterns guard violated (${allViolations.length} issue(s)):\n${lines.join("\n")}`,
      );
    }
  });
});
