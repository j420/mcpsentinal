/**
 * C9 — Excessive Filesystem Scope: AST-driven fact gathering.
 *
 * Walks the TS compiler AST for four shapes:
 *
 *   1. CallExpression of `<x>.<method>("/")` where method is in
 *      FS_LIST_METHODS, FS_READ_METHODS, or CHDIR_METHODS.
 *   2. CallExpression of bare `glob("/")` / `glob("/**")` / `walk("/")`.
 *   3. VariableDeclaration / BinaryExpression assigning a root literal
 *      to an identifier in BASE_PATH_IDENTIFIER_NAMES.
 *   4. ArrayLiteralExpression assigning `["/"]` to a base-path
 *      identifier.
 *
 * Plus a Python line-scan fallback for `os.walk("/")` / `Path("/").iterdir()`.
 *
 * Zero regex literals.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  FS_LIST_METHODS,
  FS_READ_METHODS,
  CHDIR_METHODS,
  BASE_PATH_IDENTIFIER_NAMES,
  ROOT_PATH_LITERALS,
  CHARTER_CLAMP_HELPERS,
} from "./data/config.js";

export type C9LeakKind =
  | "fs-list-root"
  | "fs-read-root"
  | "chdir-root"
  | "base-path-root"
  | "python-walk-root";

export interface FsScopeFact {
  readonly kind: C9LeakKind;
  readonly location: Location;
  readonly observed: string;
  /** True when a charter-clamp helper appears in the same source. */
  readonly clampHelperPresent: boolean;
}

export interface C9GatherResult {
  readonly mode: "absent" | "test-file" | "facts";
  readonly file: string;
  readonly facts: readonly FsScopeFact[];
}

const SYNTHETIC_FILE = "<source>";
const TEST_FILE_RUNNER_MARKERS: readonly string[] = [
  'from "vitest"',
  "from 'vitest'",
  'from "@jest/globals"',
  "from '@jest/globals'",
  "import pytest",
];
const TEST_FILE_SUITE_MARKERS: readonly string[] = [
  "\ndescribe(",
  "\nit(",
  "\ntest(",
];

export function gatherC9(context: AnalysisContext): C9GatherResult {
  const source = context.source_code;
  if (!source || source.length === 0) {
    return { mode: "absent", file: SYNTHETIC_FILE, facts: [] };
  }
  if (looksLikeTestFile(source)) {
    return { mode: "test-file", file: SYNTHETIC_FILE, facts: [] };
  }

  const file = SYNTHETIC_FILE;
  const facts: FsScopeFact[] = [];
  const clampPresent = sourceHasClampHelper(source);

  if (looksLikePython(source)) {
    collectPython(source, file, facts, clampPresent);
  } else {
    try {
      const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
      ts.forEachChild(sf, function visit(node) {
        if (ts.isCallExpression(node)) {
          inspectCall(node, sf, file, facts, clampPresent);
        }
        if (ts.isVariableDeclaration(node) && node.initializer) {
          inspectAssignment(node.name, node.initializer, sf, file, facts, clampPresent);
        }
        if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
          inspectAssignment(node.left, node.right, sf, file, facts, clampPresent);
        }
        ts.forEachChild(node, visit);
      });
    } catch {
      // Parse failure: nothing to emit.
    }
  }

  return {
    mode: facts.length > 0 ? "facts" : "absent",
    file,
    facts,
  };
}

function inspectCall(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  file: string,
  facts: FsScopeFact[],
  clampPresent: boolean,
): void {
  const callee = call.expression;
  let methodName: string | null = null;
  if (ts.isPropertyAccessExpression(callee)) {
    methodName = callee.name.text;
  } else if (ts.isIdentifier(callee)) {
    methodName = callee.text;
  }
  if (!methodName) return;

  if (call.arguments.length === 0) return;
  const first = call.arguments[0];
  if (!ts.isStringLiteral(first)) return;
  if (!ROOT_PATH_LITERALS.has(first.text)) return;

  let kind: C9LeakKind | null = null;
  if (FS_LIST_METHODS.has(methodName)) kind = "fs-list-root";
  else if (FS_READ_METHODS.has(methodName)) kind = "fs-read-root";
  else if (CHDIR_METHODS.has(methodName)) kind = "chdir-root";
  if (!kind) return;

  facts.push({
    kind,
    location: locationOf(callee, sf, file),
    observed: truncate(call.getText(sf), 160),
    clampHelperPresent: clampPresent,
  });
}

function inspectAssignment(
  lhs: ts.Node,
  rhs: ts.Node,
  sf: ts.SourceFile,
  file: string,
  facts: FsScopeFact[],
  clampPresent: boolean,
): void {
  const name = identifierTextOf(lhs);
  if (!name) return;
  if (!BASE_PATH_IDENTIFIER_NAMES.has(name) && !BASE_PATH_IDENTIFIER_NAMES.has(name.toLowerCase())) {
    // Fall through: also accept any identifier that includes "ROOT" / "BASE" / "ALLOWED"
    const lower = name.toLowerCase();
    if (!lower.includes("root") && !lower.includes("base") && !lower.includes("allowed")) return;
  }
  // RHS: string literal "/" OR ArrayLiteral whose first element is "/"
  if (ts.isStringLiteral(rhs) && ROOT_PATH_LITERALS.has(rhs.text)) {
    facts.push({
      kind: "base-path-root",
      location: locationOf(lhs, sf, file),
      observed: truncate(`${name} = ${rhs.getText(sf)}`, 160),
      clampHelperPresent: clampPresent,
    });
    return;
  }
  if (ts.isArrayLiteralExpression(rhs)) {
    for (const elem of rhs.elements) {
      if (ts.isStringLiteral(elem) && ROOT_PATH_LITERALS.has(elem.text)) {
        facts.push({
          kind: "base-path-root",
          location: locationOf(lhs, sf, file),
          observed: truncate(`${name} = ${rhs.getText(sf)}`, 160),
          clampHelperPresent: clampPresent,
        });
        return;
      }
    }
  }
}

function identifierTextOf(node: ts.Node): string | null {
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  return null;
}

function sourceHasClampHelper(text: string): boolean {
  for (const name of CHARTER_CLAMP_HELPERS) {
    if (text.includes(`${name}(`)) return true;
  }
  return false;
}

function collectPython(text: string, file: string, facts: FsScopeFact[], clampPresent: boolean): void {
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    let kind: C9LeakKind | null = null;
    let methodIdx = -1;
    if (raw.includes('os.walk("/")') || raw.includes("os.walk('/')")) {
      kind = "python-walk-root";
      methodIdx = raw.indexOf("os.walk");
    } else if (raw.includes('Path("/").iterdir(') || raw.includes("Path('/').iterdir(")) {
      kind = "python-walk-root";
      methodIdx = raw.indexOf("Path");
    } else if (raw.includes('os.chdir("/")') || raw.includes("os.chdir('/')")) {
      kind = "chdir-root";
      methodIdx = raw.indexOf("os.chdir");
    } else if (raw.includes('os.listdir("/")') || raw.includes("os.listdir('/')")) {
      kind = "fs-list-root";
      methodIdx = raw.indexOf("os.listdir");
    }
    if (kind === null) continue;
    facts.push({
      kind,
      location: { kind: "source", file, line: i + 1, col: methodIdx + 1 },
      observed: truncate(raw.trim(), 160),
      clampHelperPresent: clampPresent,
    });
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function locationOf(node: ts.Node, sf: ts.SourceFile, file: string): Location {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return { kind: "source", file, line: line + 1, col: character + 1 };
}

function looksLikeTestFile(source: string): boolean {
  const hasRunner = TEST_FILE_RUNNER_MARKERS.some((m) => source.includes(m));
  const hasSuite =
    TEST_FILE_SUITE_MARKERS.some((m) => source.includes(m)) ||
    source.startsWith("describe(") ||
    source.startsWith("it(") ||
    source.startsWith("test(");
  return hasRunner && hasSuite;
}

function looksLikePython(text: string): boolean {
  const hasDef = text.includes("\ndef ") || text.startsWith("def ");
  const hasJsKeywords =
    text.includes("const ") || text.includes("let ") || text.includes("function ");
  return hasDef && !hasJsKeywords;
}

function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}
