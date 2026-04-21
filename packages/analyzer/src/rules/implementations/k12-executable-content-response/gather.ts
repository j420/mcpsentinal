/**
 * K12 gather — executable content in tool response.
 *
 * Fires when a response-emitting call or a ReturnStatement carries an
 * executable primitive (eval / new Function / require / dynamic import /
 * script tag / javascript: URI / inline event handler) AND no sanitizer
 * call is observed in the same lexical function scope.
 *
 * Zero regex.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  EXEC_CALL_IDENTIFIERS,
  EXEC_NEW_IDENTIFIERS,
  EXEC_STRING_MARKERS,
  INLINE_EVENT_HANDLER_PREFIXES,
  SANITIZER_CALL_IDENTIFIERS,
  SANITIZER_RECEIVER_METHODS,
  RESPONSE_RECEIVERS,
  RESPONSE_METHODS,
} from "./data/exec-patterns.js";

const EXEC_CALL_SET: ReadonlySet<string> = new Set(Object.keys(EXEC_CALL_IDENTIFIERS));
const EXEC_NEW_SET: ReadonlySet<string> = new Set(Object.keys(EXEC_NEW_IDENTIFIERS));
const EXEC_STRING_MARKER_SET: ReadonlySet<string> = new Set(Object.keys(EXEC_STRING_MARKERS));
const INLINE_EVENT_PREFIX_SET: ReadonlySet<string> = new Set(Object.keys(INLINE_EVENT_HANDLER_PREFIXES));
const SANITIZER_CALL_SET: ReadonlySet<string> = new Set(Object.keys(SANITIZER_CALL_IDENTIFIERS));
const RESPONSE_RECEIVER_SET: ReadonlySet<string> = new Set(Object.keys(RESPONSE_RECEIVERS));
const RESPONSE_METHOD_SET: ReadonlySet<string> = new Set(Object.keys(RESPONSE_METHODS));

const TEST_RUNNER_MODULE_SET: ReadonlySet<string> = new Set([
  "vitest", "jest", "@jest/globals", "mocha", "node:test",
]);
const TEST_TOPLEVEL_SET: ReadonlySet<string> = new Set([
  "describe", "it", "test", "suite",
]);

export type ExecEvidenceKind =
  | "eval-call"
  | "new-function"
  | "require-call"
  | "dynamic-import"
  | "script-tag-string"
  | "javascript-uri-string"
  | "data-html-uri-string"
  | "inline-event-handler-string";

export interface ExecSite {
  location: Location;   // source
  kind: ExecEvidenceKind;
  enclosingFunctionLocation: Location | null; // source; null at file scope
  observed: string;
  siteType: "return-statement" | "response-call" | "other";
  enclosingHasSanitizer: boolean;
}

export interface FileEvidence {
  file: string;
  sites: ExecSite[];
  isTestFile: boolean;
}

export interface K12Gathered {
  perFile: FileEvidence[];
}

export function gatherK12(context: AnalysisContext): K12Gathered {
  const perFile: FileEvidence[] = [];
  const files = collectSourceFiles(context);
  for (const [file, text] of files) {
    perFile.push(gatherFile(file, text));
  }
  return { perFile };
}

function collectSourceFiles(context: AnalysisContext): Map<string, string> {
  const out = new Map<string, string>();
  if (context.source_files && context.source_files.size > 0) {
    for (const [k, v] of context.source_files) out.set(k, v);
    return out;
  }
  if (context.source_code) {
    out.set("<concatenated-source>", context.source_code);
  }
  return out;
}

function gatherFile(file: string, text: string): FileEvidence {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const isTestFile = detectTestFileStructurally(sf);
  const sites: ExecSite[] = [];

  if (!isTestFile) {
    ts.forEachChild(sf, function visit(node) {
      // Only inspect response-emitting contexts: ReturnStatement body +
      // response-call arguments. Free-floating eval() elsewhere is C1/C16.
      if (ts.isReturnStatement(node) && node.expression) {
        collectFromExpression(node.expression, "return-statement", sf, file, sites);
      }
      if (ts.isCallExpression(node) && isResponseCall(node)) {
        for (const arg of node.arguments) {
          collectFromExpression(arg, "response-call", sf, file, sites);
        }
      }
      ts.forEachChild(node, visit);
    });
  }

  return { file, sites, isTestFile };
}

function detectTestFileStructurally(sf: ts.SourceFile): boolean {
  let topLevelRunnerCalls = 0;
  let topLevelItOrTest = 0;
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
            if (callee.text === "it" || callee.text === "test") topLevelItOrTest++;
            break;
          }
        }
      }
    }
  }
  if (topLevelItOrTest > 0) return true;
  return topLevelRunnerCalls > 0 && (hasRunnerImport || topLevelRunnerCalls >= 2);
}

function isResponseCall(call: ts.CallExpression): boolean {
  if (!ts.isPropertyAccessExpression(call.expression)) return false;
  const method = call.expression.name.text.toLowerCase();
  if (!RESPONSE_METHOD_SET.has(method)) return false;
  const receiver = call.expression.expression;
  if (!ts.isIdentifier(receiver)) return false;
  return RESPONSE_RECEIVER_SET.has(receiver.text.toLowerCase());
}

function collectFromExpression(
  expr: ts.Expression,
  siteType: "return-statement" | "response-call",
  sf: ts.SourceFile,
  file: string,
  sites: ExecSite[],
): void {
  // Walk the expression subtree — executable primitives can be nested.
  visit(expr);

  function visit(n: ts.Node): void {
    const kind = classifyExecNode(n);
    if (kind) {
      const enclosing = findEnclosingFunction(n);
      const enclosingLoc: Location | null = enclosing
        ? sourceLocation(sf, file, enclosing)
        : null;
      const enclosingText = enclosing ? enclosing.getText(sf) : "";
      sites.push({
        location: sourceLocation(sf, file, n),
        kind,
        enclosingFunctionLocation: enclosingLoc,
        observed: lineTextAt(sf, n.getStart(sf)).trim().slice(0, 200),
        siteType,
        enclosingHasSanitizer: enclosingHasSanitizerCall(enclosingText, enclosing),
      });
    }
    ts.forEachChild(n, visit);
  }
}

function classifyExecNode(node: ts.Node): ExecEvidenceKind | null {
  if (ts.isCallExpression(node)) {
    if (ts.isIdentifier(node.expression)) {
      const id = node.expression.text.toLowerCase();
      if (id === "eval" && EXEC_CALL_SET.has("eval")) return "eval-call";
      if (id === "require" && EXEC_CALL_SET.has("require")) return "require-call";
    }
    if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      return "dynamic-import";
    }
  }
  if (ts.isNewExpression(node) && ts.isIdentifier(node.expression)) {
    if (EXEC_NEW_SET.has(node.expression.text.toLowerCase())) return "new-function";
  }
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
    return classifyStringMarker(node.text);
  }
  return null;
}

function classifyStringMarker(text: string): ExecEvidenceKind | null {
  const lower = text.toLowerCase();
  for (const marker of EXEC_STRING_MARKER_SET) {
    if (lower.includes(marker)) {
      if (marker === "<script" || marker === "</script") return "script-tag-string";
      if (marker === "javascript:") return "javascript-uri-string";
      if (marker === "data:text/html") return "data-html-uri-string";
    }
  }
  if (containsInlineEventHandler(lower)) return "inline-event-handler-string";
  return null;
}

/**
 * Detect `on<event>=` or `on<event>="..."` inline event handlers without
 * regex. Walk characters looking for "on" followed by letters followed by
 * "=" or " =".
 */
function containsInlineEventHandler(text: string): boolean {
  for (let i = 0; i < text.length - 4; i++) {
    if (text[i] !== "o") continue;
    if (text[i + 1] !== "n") continue;
    let j = i + 2;
    while (j < text.length && text[j] >= "a" && text[j] <= "z") j++;
    if (j === i + 2) continue;
    const attrName = text.slice(i, j);
    if (!INLINE_EVENT_PREFIX_SET.has(attrName)) continue;
    // Skip whitespace, then require '='.
    let k = j;
    while (k < text.length && (text[k] === " " || text[k] === "\t")) k++;
    if (text[k] === "=") return true;
  }
  return false;
}

function findEnclosingFunction(node: ts.Node): ts.Node | null {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isMethodDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur)
    ) {
      return cur;
    }
    cur = cur.parent;
  }
  return null;
}

/**
 * AST walk of the enclosing function body: any CallExpression whose
 * callee tokenises to a sanitizer identifier, or any receiver.method
 * matching the sanitizer receiver/method vocabulary.
 */
function enclosingHasSanitizerCall(_enclosingText: string, enclosing: ts.Node | null): boolean {
  if (!enclosing) return false;
  let found = false;
  function visit(n: ts.Node): void {
    if (found) return;
    if (ts.isCallExpression(n)) {
      if (ts.isIdentifier(n.expression)) {
        if (SANITIZER_CALL_SET.has(n.expression.text.toLowerCase())) {
          found = true;
          return;
        }
      }
      if (ts.isPropertyAccessExpression(n.expression)) {
        const recvNode = n.expression.expression;
        const method = n.expression.name.text.toLowerCase();
        if (ts.isIdentifier(recvNode)) {
          const recv = recvNode.text.toLowerCase();
          const methods = SANITIZER_RECEIVER_METHODS[recv];
          if (methods && methods[method]) {
            found = true;
            return;
          }
        }
      }
    }
    ts.forEachChild(n, visit);
  }
  ts.forEachChild(enclosing, visit);
  return found;
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
