/**
 * C15 — Timing Attack: AST-driven fact gathering.
 *
 * Walks the TS compiler AST for two shapes:
 *
 *   1. BinaryExpression with operator === / == / !== / !=
 *      - one side is a secret-named identifier (or a property access
 *        whose tail is a secret-named identifier),
 *      - the other side is a request-derived expression (identifier
 *        whose name contains "req" / "request" / "header" / "input"
 *        OR a property access whose root is one of those).
 *
 *   2. CallExpression of `<x>.<method>(<y>)` where method is in
 *      SHORT_CIRCUIT_METHODS and one of (<x>, <y>) is secret-named
 *      and the other is request-derived.
 *
 * Plus a Python line-scan for `==` between secret-named and
 * request-derived identifiers.
 *
 * Mitigation marker: presence of `timingSafeEqual` /
 * `hmac.compare_digest` etc. anywhere in the source.
 *
 * Zero regex literals.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  SECRET_IDENTIFIER_NAMES,
  REQUEST_IDENTIFIER_FRAGMENTS,
  SHORT_CIRCUIT_METHODS,
  TIMING_SAFE_MARKERS,
} from "./data/config.js";

export type C15LeakKind =
  | "strict-equality"
  | "loose-equality"
  | "starts-ends-with"
  | "python-equality";

export interface TimingFact {
  readonly kind: C15LeakKind;
  readonly location: Location;
  readonly observed: string;
  readonly secretSide: string;
  readonly requestSide: string;
  readonly mitigationPresent: boolean;
}

export interface C15GatherResult {
  readonly mode: "absent" | "test-file" | "facts";
  readonly file: string;
  readonly facts: readonly TimingFact[];
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

export function gatherC15(context: AnalysisContext): C15GatherResult {
  const source = context.source_code;
  if (!source || source.length === 0) {
    return { mode: "absent", file: SYNTHETIC_FILE, facts: [] };
  }
  if (looksLikeTestFile(source)) {
    return { mode: "test-file", file: SYNTHETIC_FILE, facts: [] };
  }

  const file = SYNTHETIC_FILE;
  const facts: TimingFact[] = [];
  const mitigationPresent = sourceHasTimingSafe(source);

  if (looksLikePython(source)) {
    collectPython(source, file, facts, mitigationPresent);
  } else {
    try {
      const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
      ts.forEachChild(sf, function visit(node) {
        if (ts.isBinaryExpression(node)) {
          inspectBinary(node, sf, file, facts, mitigationPresent);
        }
        if (ts.isCallExpression(node)) {
          inspectShortCircuitMethod(node, sf, file, facts, mitigationPresent);
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

function inspectBinary(
  node: ts.BinaryExpression,
  sf: ts.SourceFile,
  file: string,
  facts: TimingFact[],
  mitigationPresent: boolean,
): void {
  const op = node.operatorToken.kind;
  const isStrict = op === ts.SyntaxKind.EqualsEqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsEqualsToken;
  const isLoose = op === ts.SyntaxKind.EqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsToken;
  if (!isStrict && !isLoose) return;

  const left = expressionTail(node.left);
  const right = expressionTail(node.right);
  if (!left || !right) return;

  const leftSecret = isSecretIdentifier(left);
  const rightSecret = isSecretIdentifier(right);
  const leftRequest = isRequestExpression(node.left);
  const rightRequest = isRequestExpression(node.right);

  let secretSide: string | null = null;
  let requestSide: string | null = null;
  if (leftSecret && rightRequest) {
    secretSide = left;
    requestSide = node.right.getText(sf);
  } else if (rightSecret && leftRequest) {
    secretSide = right;
    requestSide = node.left.getText(sf);
  }
  if (secretSide === null || requestSide === null) return;

  facts.push({
    kind: isStrict ? "strict-equality" : "loose-equality",
    location: locationOf(node, sf, file),
    observed: truncate(node.getText(sf), 160),
    secretSide,
    requestSide,
    mitigationPresent,
  });
}

function inspectShortCircuitMethod(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  file: string,
  facts: TimingFact[],
  mitigationPresent: boolean,
): void {
  const callee = call.expression;
  if (!ts.isPropertyAccessExpression(callee)) return;
  if (!SHORT_CIRCUIT_METHODS.has(callee.name.text)) return;
  if (call.arguments.length === 0) return;

  const recvText = expressionTail(callee.expression);
  const argExpr = call.arguments[0];
  const argText = expressionTail(argExpr);
  if (!recvText || !argText) return;

  const recvSecret = isSecretIdentifier(recvText);
  const recvRequest = isRequestExpression(callee.expression);
  const argSecret = isSecretIdentifier(argText);
  const argRequest = isRequestExpression(argExpr);

  let secretSide: string | null = null;
  let requestSide: string | null = null;
  if (recvSecret && argRequest) {
    secretSide = recvText;
    requestSide = argExpr.getText(sf);
  } else if (argSecret && recvRequest) {
    secretSide = argText;
    requestSide = callee.expression.getText(sf);
  }
  if (secretSide === null || requestSide === null) return;

  facts.push({
    kind: "starts-ends-with",
    location: locationOf(call, sf, file),
    observed: truncate(call.getText(sf), 160),
    secretSide,
    requestSide,
    mitigationPresent,
  });
}

function expressionTail(node: ts.Node): string | null {
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  if (ts.isElementAccessExpression(node) && ts.isStringLiteral(node.argumentExpression)) {
    return node.argumentExpression.text;
  }
  return null;
}

function isSecretIdentifier(name: string): boolean {
  if (SECRET_IDENTIFIER_NAMES.has(name)) return true;
  const lower = name.toLowerCase();
  if (SECRET_IDENTIFIER_NAMES.has(lower)) return true;
  // Cheap fallback: any identifier ending in "Token" / "Secret" / "Key" /
  // "Hmac" / "Digest" / "Hash" / "Password".
  for (const tail of ["token", "secret", "key", "hmac", "digest", "hash", "password", "signature"]) {
    if (lower.endsWith(tail)) return true;
  }
  return false;
}

function isRequestExpression(node: ts.Node): boolean {
  // Walk up property chains: req.headers.authorization → root identifier "req"
  let cur: ts.Node = node;
  while (ts.isPropertyAccessExpression(cur) || ts.isElementAccessExpression(cur)) {
    cur = cur.expression;
  }
  if (ts.isIdentifier(cur)) {
    const lower = cur.text.toLowerCase();
    for (const frag of REQUEST_IDENTIFIER_FRAGMENTS) {
      if (lower === frag) return true;
      if (lower.startsWith(frag)) return true;
    }
  }
  return false;
}

function sourceHasTimingSafe(text: string): boolean {
  for (const marker of TIMING_SAFE_MARKERS) {
    if (text.includes(marker)) return true;
  }
  return false;
}

function collectPython(text: string, file: string, facts: TimingFact[], mitigationPresent: boolean): void {
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    // Look for `==` operators outside of comments / docstrings.
    const trimmed = raw.trim();
    if (trimmed.startsWith("#")) continue;
    const eqIdx = findPythonEquality(raw);
    if (eqIdx < 0) continue;
    const lhs = raw.slice(0, eqIdx).trim();
    const rhs = raw.slice(eqIdx + 2).trim();
    const lhsTail = pythonTailIdentifier(lhs);
    const rhsTail = pythonTailIdentifier(rhs);
    if (!lhsTail || !rhsTail) continue;

    const lhsSecret = isSecretIdentifier(lhsTail);
    const rhsSecret = isSecretIdentifier(rhsTail);
    const lhsRequest = pythonExpressionLooksLikeRequest(lhs);
    const rhsRequest = pythonExpressionLooksLikeRequest(rhs);

    let secretSide: string | null = null;
    let requestSide: string | null = null;
    if (lhsSecret && rhsRequest) {
      secretSide = lhsTail;
      requestSide = rhs;
    } else if (rhsSecret && lhsRequest) {
      secretSide = rhsTail;
      requestSide = lhs;
    }
    if (secretSide === null || requestSide === null) continue;

    facts.push({
      kind: "python-equality",
      location: { kind: "source", file, line: i + 1, col: eqIdx + 1 },
      observed: truncate(trimmed, 160),
      secretSide,
      requestSide,
      mitigationPresent,
    });
  }
}

function findPythonEquality(line: string): number {
  // Find first `==` not inside a string literal. Simple scanner.
  let i = 0;
  let inString: '"' | "'" | null = null;
  while (i < line.length - 1) {
    const c = line[i];
    if (inString) {
      if (c === "\\") {
        i += 2;
        continue;
      }
      if (c === inString) inString = null;
      i++;
      continue;
    }
    if (c === '"' || c === "'") {
      inString = c;
      i++;
      continue;
    }
    if (c === "=" && line[i + 1] === "=" && line[i + 2] !== "=") {
      // Make sure it's not part of `===` or assignment-then-equality (not a thing in Python).
      // Also reject `!=` (handled separately) and `>=`/`<=`.
      const prev = line[i - 1] ?? " ";
      if (prev === "!" || prev === ">" || prev === "<" || prev === "=") {
        i++;
        continue;
      }
      return i;
    }
    i++;
  }
  return -1;
}

function pythonTailIdentifier(expr: string): string | null {
  // Strip whitespace + parens without using a regex literal (the
  // no-static-patterns guard rejects regex in implementation files).
  let cleaned = "";
  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i];
    if (ch === " " || ch === "\t" || ch === "(" || ch === ")") continue;
    cleaned += ch;
  }
  // Walk from the end past trailing non-identifier punctuation
  // (`:`, `,`, `;`, `]`, `}`) before extracting the trailing identifier.
  let end = cleaned.length;
  while (end > 0) {
    const cp = cleaned.charCodeAt(end - 1);
    const isIdent =
      (cp >= 48 && cp <= 57) ||
      (cp >= 65 && cp <= 90) ||
      (cp >= 97 && cp <= 122) ||
      cp === 95;
    if (isIdent) break;
    end--;
  }
  let start = end;
  while (start > 0) {
    const cp = cleaned.charCodeAt(start - 1);
    if (
      (cp >= 48 && cp <= 57) ||
      (cp >= 65 && cp <= 90) ||
      (cp >= 97 && cp <= 122) ||
      cp === 95
    ) {
      start--;
    } else {
      break;
    }
  }
  if (start === end) return null;
  return cleaned.slice(start, end);
}

function pythonExpressionLooksLikeRequest(expr: string): boolean {
  const lower = expr.toLowerCase();
  for (const frag of REQUEST_IDENTIFIER_FRAGMENTS) {
    if (lower.startsWith(frag) || lower.includes(`.${frag}`) || lower.includes(`${frag}.`) || lower.includes(`${frag}[`)) {
      return true;
    }
  }
  return false;
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
