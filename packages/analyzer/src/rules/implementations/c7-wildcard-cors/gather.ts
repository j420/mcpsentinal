/**
 * C7 — Wildcard CORS: AST-driven fact gathering.
 *
 * Walks the TS compiler AST for three patterns:
 *
 *   1. CallExpression of an identifier whose name is in
 *      CORS_FUNCTION_NAMES. The first argument (if any) is an
 *      ObjectLiteralExpression whose `origin` property is examined:
 *      "*" / true / a function returning true unconditionally / no
 *      key (defaults to *) all fire.
 *
 *   2. CallExpression of `<receiver>.<method>(...)` where method is
 *      in HEADER_SET_METHODS and the first argument's lowercase
 *      string value equals ACAO_HEADER_NAME and the second argument
 *      is the literal "*".
 *
 *   3. Python `CORS(app, origins="*")` / `@cross_origin(origin="*")`
 *      via line scan (the TS parser does not understand Python
 *      syntax for keyword arguments).
 *
 * Every emitted CorsLeakFact carries a structured Location.
 *
 * Zero regex literals.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  CORS_FUNCTION_NAMES,
  HEADER_SET_METHODS,
  ACAO_HEADER_NAME,
  ACAC_HEADER_NAME,
  PYTHON_CORS_NAMES,
} from "./data/config.js";

export type CorsLeakKind =
  | "cors-options-wildcard"
  | "cors-options-reflected"
  | "cors-no-arguments"
  | "set-header-wildcard"
  | "python-cors-wildcard";

export interface CorsLeakFact {
  readonly kind: CorsLeakKind;
  readonly location: Location;
  readonly observed: string;
  /** True when the same options literal sets credentials: true. */
  readonly credentialsFlag: boolean;
}

export interface C7GatherResult {
  readonly mode: "absent" | "test-file" | "facts";
  readonly file: string;
  readonly facts: readonly CorsLeakFact[];
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

export function gatherC7(context: AnalysisContext): C7GatherResult {
  const source = context.source_code;
  if (!source || source.length === 0) {
    return { mode: "absent", file: SYNTHETIC_FILE, facts: [] };
  }
  if (looksLikeTestFile(source)) {
    return { mode: "test-file", file: SYNTHETIC_FILE, facts: [] };
  }

  const file = SYNTHETIC_FILE;
  const facts: CorsLeakFact[] = [];

  const isPython = looksLikePython(source);
  if (isPython) {
    collectPython(source, file, facts);
  } else {
    try {
      const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
      ts.forEachChild(sf, function visit(node) {
        if (ts.isCallExpression(node)) {
          inspectCorsCall(node, sf, file, facts);
          inspectSetHeaderCall(node, sf, file, facts);
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

function inspectCorsCall(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  file: string,
  facts: CorsLeakFact[],
): void {
  const callee = call.expression;
  let name: string | null = null;
  if (ts.isIdentifier(callee)) name = callee.text;
  else if (ts.isPropertyAccessExpression(callee)) name = callee.name.text;
  if (!name || !CORS_FUNCTION_NAMES.has(name)) return;

  // Pattern: cors() — defaults to wildcard
  if (call.arguments.length === 0) {
    facts.push({
      kind: "cors-no-arguments",
      location: locationOf(callee, sf, file),
      observed: truncate(call.getText(sf), 160),
      credentialsFlag: false,
    });
    return;
  }

  const first = call.arguments[0];
  if (!ts.isObjectLiteralExpression(first)) return;

  const credentialsFlag = hasCredentialsTrue(first);

  // Find `origin` property
  let originProp: ts.PropertyAssignment | null = null;
  for (const prop of first.properties) {
    if (ts.isPropertyAssignment(prop) && getPropName(prop.name) === "origin") {
      originProp = prop;
      break;
    }
  }

  // No origin key → defaults to *
  if (!originProp) {
    facts.push({
      kind: "cors-options-wildcard",
      location: locationOf(callee, sf, file),
      observed: truncate(call.getText(sf), 160),
      credentialsFlag,
    });
    return;
  }

  const init = originProp.initializer;
  // origin: "*"
  if (ts.isStringLiteral(init) && init.text === "*") {
    facts.push({
      kind: "cors-options-wildcard",
      location: locationOf(originProp, sf, file),
      observed: truncate(originProp.getText(sf), 160),
      credentialsFlag,
    });
    return;
  }
  // origin: true → reflects any origin
  if (init.kind === ts.SyntaxKind.TrueKeyword) {
    facts.push({
      kind: "cors-options-reflected",
      location: locationOf(originProp, sf, file),
      observed: truncate(originProp.getText(sf), 160),
      credentialsFlag,
    });
    return;
  }
  // origin: (origin, cb) => cb(null, true) → unconditionally returns true
  if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) {
    if (functionUnconditionallyReturnsTrue(init)) {
      facts.push({
        kind: "cors-options-reflected",
        location: locationOf(originProp, sf, file),
        observed: truncate(originProp.getText(sf), 160),
        credentialsFlag,
      });
    }
  }
}

function functionUnconditionallyReturnsTrue(
  fn: ts.ArrowFunction | ts.FunctionExpression,
): boolean {
  // Arrow body: (...) => cb(null, true)
  if (ts.isArrowFunction(fn) && !ts.isBlock(fn.body)) {
    const body = fn.body;
    if (ts.isCallExpression(body)) {
      // cb(null, true)  /  cb(undefined, true)
      const args = body.arguments;
      if (args.length === 2 && args[1].kind === ts.SyntaxKind.TrueKeyword) {
        return true;
      }
    }
    if (body.kind === ts.SyntaxKind.TrueKeyword) return true;
  }
  // Block body: { return true; } / { cb(null, true); }
  if (ts.isBlock(fn.body)) {
    for (const stmt of fn.body.statements) {
      if (ts.isReturnStatement(stmt) && stmt.expression?.kind === ts.SyntaxKind.TrueKeyword) {
        return true;
      }
      if (ts.isExpressionStatement(stmt) && ts.isCallExpression(stmt.expression)) {
        const call = stmt.expression;
        if (call.arguments.length === 2 && call.arguments[1].kind === ts.SyntaxKind.TrueKeyword) {
          return true;
        }
      }
    }
  }
  return false;
}

function hasCredentialsTrue(obj: ts.ObjectLiteralExpression): boolean {
  for (const prop of obj.properties) {
    if (ts.isPropertyAssignment(prop) && getPropName(prop.name) === "credentials") {
      if (prop.initializer.kind === ts.SyntaxKind.TrueKeyword) return true;
    }
  }
  return false;
}

function inspectSetHeaderCall(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  file: string,
  facts: CorsLeakFact[],
): void {
  const callee = call.expression;
  if (!ts.isPropertyAccessExpression(callee)) return;
  const method = callee.name.text;
  if (!HEADER_SET_METHODS.has(method)) return;
  if (call.arguments.length < 2) return;
  const headerArg = call.arguments[0];
  const valueArg = call.arguments[1];
  if (!ts.isStringLiteral(headerArg)) return;
  if (headerArg.text.toLowerCase() !== ACAO_HEADER_NAME) return;
  if (!ts.isStringLiteral(valueArg)) return;
  if (valueArg.text !== "*") return;
  facts.push({
    kind: "set-header-wildcard",
    location: locationOf(call, sf, file),
    observed: truncate(call.getText(sf), 160),
    credentialsFlag: containsCredentialsHeader(sf),
  });
}

/** Best-effort: does any sibling setHeader call set credentials true? */
function containsCredentialsHeader(sf: ts.SourceFile): boolean {
  let found = false;
  ts.forEachChild(sf, function visit(node) {
    if (found) return;
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      HEADER_SET_METHODS.has(node.expression.name.text) &&
      node.arguments.length >= 2 &&
      ts.isStringLiteral(node.arguments[0]) &&
      node.arguments[0].text.toLowerCase() === ACAC_HEADER_NAME &&
      ts.isStringLiteral(node.arguments[1]) &&
      node.arguments[1].text.toLowerCase() === "true"
    ) {
      found = true;
    }
    ts.forEachChild(node, visit);
  });
  return found;
}

function collectPython(text: string, file: string, facts: CorsLeakFact[]): void {
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    let matchedName: string | null = null;
    for (const name of PYTHON_CORS_NAMES) {
      if (raw.includes(`${name}(`)) {
        matchedName = name;
        break;
      }
    }
    if (!matchedName) continue;
    // Look for origins="*" / origins='*' / origin="*" / origin='*' in the same line.
    const lower = raw;
    const wildcards = [
      'origins="*"',
      "origins='*'",
      "origin=\"*\"",
      "origin='*'",
    ];
    let matchedWildcard = false;
    for (const w of wildcards) {
      if (lower.includes(w)) {
        matchedWildcard = true;
        break;
      }
    }
    // Bare `CORS(app)` with no kwargs — flask_cors default is wildcard.
    const isBareCall = raw.includes(`${matchedName}(app)`) || raw.includes(`${matchedName}(self.app)`);
    if (!matchedWildcard && !isBareCall) continue;

    const idx = raw.indexOf(matchedName);
    const credentialsFlag = lower.includes("supports_credentials=True");
    facts.push({
      kind: "python-cors-wildcard",
      location: { kind: "source", file, line: i + 1, col: idx + 1 },
      observed: truncate(raw.trim(), 160),
      credentialsFlag,
    });
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function getPropName(name: ts.PropertyName): string {
  if (ts.isIdentifier(name)) return name.text;
  if (ts.isStringLiteral(name)) return name.text;
  return "";
}

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
