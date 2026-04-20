/**
 * K17 AST walker — HTTP-call site collection + file-level global timeout
 * analysis. Zero regex.
 */

import ts from "typescript";
import type { Location } from "../../location.js";
import {
  BARE_HTTP_CALLS,
  HTTP_CLIENT_RECEIVERS,
  HTTP_CLIENT_METHODS,
  RECEIVER_GLOBAL_TIMEOUT_PROPERTIES,
  RECEIVER_FACTORY_TIMEOUT_METHODS,
} from "./data/http-clients.js";
import {
  CALL_TIMEOUT_OPTIONS,
  ABORT_CONSTRUCTORS,
  ABORT_SIGNAL_METHODS,
} from "./data/timeout-options.js";
import type { FileEvidence, HttpCallSite } from "./gather.js";

const BARE_HTTP_CALL_SET: ReadonlySet<string> = new Set(Object.keys(BARE_HTTP_CALLS));
const HTTP_RECEIVER_SET: ReadonlySet<string> = new Set(Object.keys(HTTP_CLIENT_RECEIVERS));
const HTTP_METHOD_SET: ReadonlySet<string> = new Set(Object.keys(HTTP_CLIENT_METHODS));
const CALL_TIMEOUT_OPTION_SET: ReadonlySet<string> = new Set(Object.keys(CALL_TIMEOUT_OPTIONS));
const ABORT_CONSTRUCTOR_SET: ReadonlySet<string> = new Set(Object.keys(ABORT_CONSTRUCTORS));
const ABORT_SIGNAL_METHOD_SET: ReadonlySet<string> = new Set(Object.keys(ABORT_SIGNAL_METHODS));

const TEST_RUNNER_MODULE_SET: ReadonlySet<string> = new Set([
  "vitest", "jest", "@jest/globals", "mocha", "node:test",
]);
const TEST_TOPLEVEL_SET: ReadonlySet<string> = new Set([
  "describe", "it", "test", "suite",
]);

export function gatherFile(file: string, text: string): FileEvidence {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const isTestFile = detectTestFileStructurally(sf);

  const calls: HttpCallSite[] = [];
  let hasGlobalAxiosTimeout = false;
  let hasGlobalGotTimeout = false;
  let hasGlobalKyTimeout = false;

  // First pass: collect global-timeout signals from the file as a whole.
  ts.forEachChild(sf, function visit(node) {
    // axios.defaults.timeout = N
    if (isGlobalDefaultsTimeoutAssignment(node, "axios")) hasGlobalAxiosTimeout = true;

    // axios.create({ timeout: N }) / got.extend({ timeout: N }) / ky.create(...)
    if (ts.isCallExpression(node)) {
      const factory = classifyFactoryTimeout(node);
      if (factory === "axios") hasGlobalAxiosTimeout = true;
      if (factory === "got") hasGlobalGotTimeout = true;
      if (factory === "ky") hasGlobalKyTimeout = true;
    }

    ts.forEachChild(node, visit);
  });

  // Second pass: collect HTTP-call sites (skipped in test files).
  if (!isTestFile) {
    ts.forEachChild(sf, function visit(node) {
      if (ts.isCallExpression(node)) {
        const site = inspectHttpCall(node, sf, file);
        if (site) calls.push(site);
      }
      ts.forEachChild(node, visit);
    });
  }

  return {
    file,
    calls,
    hasGlobalAxiosTimeout,
    hasGlobalGotTimeout,
    hasGlobalKyTimeout,
    isTestFile,
  };
}

// ─── Test-file structural detection ────────────────────────────────────────

function detectTestFileStructurally(sf: ts.SourceFile): boolean {
  let topLevelRunnerCalls = 0;
  let topLevelItOrTestCalls = 0;
  let hasRunnerImport = false;
  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)) {
      if (TEST_RUNNER_MODULE_SET.has(stmt.moduleSpecifier.text)) hasRunnerImport = true;
    }
    if (ts.isExpressionStatement(stmt) && ts.isCallExpression(stmt.expression)) {
      const callee = stmt.expression.expression;
      if (ts.isIdentifier(callee) && TEST_TOPLEVEL_SET.has(callee.text)) {
        for (const arg of stmt.expression.arguments) {
          if (ts.isArrowFunction(arg) || ts.isFunctionExpression(arg)) {
            topLevelRunnerCalls++;
            if (callee.text === "it" || callee.text === "test") {
              topLevelItOrTestCalls++;
            }
            break;
          }
        }
      }
    }
  }
  // `it(...)` or `test(...)` at the top level is an unambiguous test marker —
  // those names only appear in test frameworks. A bare `describe(...)` is
  // slightly more ambiguous; require corroborating signals for it.
  if (topLevelItOrTestCalls > 0) return true;
  return topLevelRunnerCalls > 0 && (hasRunnerImport || topLevelRunnerCalls >= 2);
}

// ─── HTTP call inspection ─────────────────────────────────────────────────

function inspectHttpCall(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  file: string,
): HttpCallSite | null {
  const client = classifyHttpCall(call.expression);
  if (!client) return null;

  const hasCallTimeoutOption = callArgsCarryTimeout(call);
  const hasEnclosingAbortSignal = hasAbortSignalInEnclosingScope(call);

  const loc = sourceLocation(sf, file, call);
  const observed = lineTextAt(sf, call.getStart(sf)).trim().slice(0, 200);

  return {
    location: loc,
    clientLabel: client,
    observed,
    hasCallTimeoutOption,
    hasEnclosingAbortSignal,
  };
}

function classifyHttpCall(callee: ts.Expression): string | null {
  if (ts.isIdentifier(callee)) {
    const name = callee.text.toLowerCase();
    if (BARE_HTTP_CALL_SET.has(name)) return callee.text;
    // Bare receiver call (axios(url)) is legitimate for some libraries
    if (HTTP_RECEIVER_SET.has(name)) return callee.text;
    return null;
  }
  if (ts.isPropertyAccessExpression(callee)) {
    const methodName = callee.name.text.toLowerCase();
    if (!HTTP_METHOD_SET.has(methodName)) return null;
    const receiverName = receiverBaseIdentifier(callee.expression);
    if (!receiverName) return null;
    const receiverLower = receiverName.toLowerCase();
    if (!HTTP_RECEIVER_SET.has(receiverLower)) return null;
    return `${receiverName}.${callee.name.text}`;
  }
  return null;
}

/** Walk a PropertyAccessExpression / Identifier down to the root receiver. */
function receiverBaseIdentifier(expr: ts.Expression): string | null {
  let cursor: ts.Expression = expr;
  while (ts.isPropertyAccessExpression(cursor)) {
    cursor = cursor.expression;
  }
  if (ts.isIdentifier(cursor)) return cursor.text;
  return null;
}

function callArgsCarryTimeout(call: ts.CallExpression): boolean {
  for (const arg of call.arguments) {
    if (!ts.isObjectLiteralExpression(arg)) continue;
    for (const prop of arg.properties) {
      if (!ts.isPropertyAssignment(prop)) continue;
      const name = propertyNameText(prop.name);
      if (!name) continue;
      if (CALL_TIMEOUT_OPTION_SET.has(name.toLowerCase())) return true;
    }
  }
  return false;
}

// ─── AbortSignal in enclosing scope ───────────────────────────────────────

function hasAbortSignalInEnclosingScope(call: ts.CallExpression): boolean {
  let current: ts.Node | undefined = call.parent;
  while (current) {
    if (ts.isBlock(current) || ts.isSourceFile(current)) {
      if (blockHasAbortSignal(current)) return true;
    }
    // Only climb to the nearest function / arrow function / method body,
    // plus the source-file top level.
    current = current.parent;
  }
  return false;
}

function blockHasAbortSignal(block: ts.Block | ts.SourceFile): boolean {
  let ctorSeen = false;
  let signalReferenced = false;
  const statements = block.statements;

  for (const stmt of statements) {
    // Recursively walk each statement looking for constructor + reference.
    visit(stmt);
    if (ctorSeen && signalReferenced) return true;
  }
  return ctorSeen && signalReferenced;

  function visit(node: ts.Node): void {
    if (ctorSeen && signalReferenced) return;
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression)) {
      if (ABORT_CONSTRUCTOR_SET.has(node.expression.text.toLowerCase())) ctorSeen = true;
    }
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const recv = node.expression.expression;
      const method = node.expression.name.text.toLowerCase();
      if (ts.isIdentifier(recv) && ABORT_CONSTRUCTOR_SET.has(recv.text.toLowerCase())) {
        if (ABORT_SIGNAL_METHOD_SET.has(method)) ctorSeen = true;
      }
    }
    if (ts.isPropertyAccessExpression(node)) {
      if (node.name.text === "signal") signalReferenced = true;
    }
    ts.forEachChild(node, visit);
  }
}

// ─── Global timeout detection ─────────────────────────────────────────────

function isGlobalDefaultsTimeoutAssignment(node: ts.Node, receiverWanted: string): boolean {
  if (!ts.isExpressionStatement(node)) return false;
  const expr = node.expression;
  if (!ts.isBinaryExpression(expr)) return false;
  if (expr.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return false;
  if (!ts.isPropertyAccessExpression(expr.left)) return false;
  if (expr.left.name.text.toLowerCase() !== "timeout") return false;

  let cursor: ts.Expression = expr.left.expression;
  while (ts.isPropertyAccessExpression(cursor)) {
    cursor = cursor.expression;
  }
  return ts.isIdentifier(cursor) && cursor.text.toLowerCase() === receiverWanted;
}

function classifyFactoryTimeout(call: ts.CallExpression): string | null {
  if (!ts.isPropertyAccessExpression(call.expression)) return null;
  const method = call.expression.name.text.toLowerCase();
  const receiver = call.expression.expression;
  if (!ts.isIdentifier(receiver)) return null;
  const receiverLower = receiver.text.toLowerCase();
  const methods = RECEIVER_FACTORY_TIMEOUT_METHODS[receiverLower];
  if (!methods || !methods[method]) return null;

  const firstArg = call.arguments[0];
  if (!firstArg || !ts.isObjectLiteralExpression(firstArg)) return null;

  // Check every property for "timeout" (case-insensitive)
  for (const prop of firstArg.properties) {
    if (!ts.isPropertyAssignment(prop)) continue;
    const name = propertyNameText(prop.name);
    if (!name) continue;
    if (name.toLowerCase() === "timeout") return receiverLower;
  }
  return null;
}

// ─── AST helpers ──────────────────────────────────────────────────────────

function propertyNameText(name: ts.PropertyName): string | null {
  if (ts.isIdentifier(name)) return name.text;
  if (ts.isStringLiteral(name) || ts.isNoSubstitutionTemplateLiteral(name)) return name.text;
  return null;
}

function sourceLocation(sf: ts.SourceFile, file: string, node: ts.Node): Location {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return { kind: "source", file, line: line + 1, col: character + 1 };
}

function lineTextAt(sf: ts.SourceFile, pos: number): string {
  const { line } = sf.getLineAndCharacterOfPosition(pos);
  const lines = sf.text.split("\n");
  return lines[line] ?? "";
}
