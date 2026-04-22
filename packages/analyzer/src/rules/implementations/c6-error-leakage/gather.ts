/**
 * C6 — Error Leakage: AST-driven fact gathering.
 *
 * Walks the TypeScript AST (via the TS compiler API) for every
 * CallExpression of the form `<receiver>.<method>(...)` where
 * `<method>` is a response-sink method name (json/send/write/end/status).
 * For each such call, checks each argument expression for any of the
 * five leak shapes documented in CHARTER lethal_edge_cases:
 *
 *   1. A bare identifier whose name is in ERROR_IDENTIFIER_NAMES.
 *   2. A property access `<x>.stack` / `<x>.stackTrace` etc.
 *   3. A call to `JSON.stringify(<error>)`.
 *   4. An ObjectLiteralExpression containing one of the above as an
 *      assignment, shorthand property, or spread element.
 *   5. A Python `traceback.format_exc()` call (handled via line scan
 *      since the TS parser does not understand Python).
 *
 * Each emitted ErrorLeakFact carries a structured Location for the
 * source position and the surrounding sink call. The orchestrator
 * (index.ts) converts facts into v2 RuleResults with evidence chains.
 *
 * Zero regex literals. No string-literal arrays > 5 — all sets live
 * in data/config.ts.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  RESPONSE_SINK_METHODS,
  ERROR_IDENTIFIER_NAMES,
  SENSITIVE_ERROR_PROPERTIES,
  PYTHON_TRACEBACK_CALLS,
  CHARTER_ERROR_SANITISERS,
  PRODUCTION_GATE_MARKERS,
} from "./data/config.js";

// ─── Public types ──────────────────────────────────────────────────────────

export type ErrorLeakKind =
  | "error-identifier"
  | "stack-property"
  | "json-stringify-error"
  | "spread-error"
  | "python-traceback";

export interface ErrorLeakFact {
  readonly kind: ErrorLeakKind;
  readonly sinkLocation: Location;
  /** Sink call expression text (truncated). */
  readonly sinkObserved: string;
  /** Method name on the receiver (json / send / write / end / status). */
  readonly sinkMethod: string;
  /** Position of the leaking source expression. */
  readonly sourceLocation: Location;
  /** Source expression text (truncated). */
  readonly sourceObserved: string;
  /** Whether the call sits inside a non-production env gate. */
  readonly productionGated: boolean;
  /** Whether a charter-audited sanitiser wraps the source. */
  readonly sanitised: boolean;
  /** Sanitiser name when sanitised is true. */
  readonly sanitiserName: string | null;
}

export interface C6GatherResult {
  readonly mode: "absent" | "test-file" | "facts";
  readonly file: string;
  readonly facts: readonly ErrorLeakFact[];
}

// ─── Constants ─────────────────────────────────────────────────────────────

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

// ─── Gather ──────────────────────────────────────────────────────────────

export function gatherC6(context: AnalysisContext): C6GatherResult {
  const source = context.source_code;
  if (!source || source.length === 0) {
    return { mode: "absent", file: SYNTHETIC_FILE, facts: [] };
  }
  if (looksLikeTestFile(source)) {
    return { mode: "test-file", file: SYNTHETIC_FILE, facts: [] };
  }

  const facts: ErrorLeakFact[] = [];
  const file = SYNTHETIC_FILE;

  const isPython = looksLikePython(source);
  if (isPython) {
    collectPythonFacts(source, file, facts);
  } else {
    try {
      const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
      ts.forEachChild(sf, function visit(node) {
        if (ts.isCallExpression(node)) {
          inspectCall(node, sf, source, file, facts);
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

// ─── TS AST inspection ────────────────────────────────────────────────────

function inspectCall(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  text: string,
  file: string,
  facts: ErrorLeakFact[],
): void {
  const callee = call.expression;
  if (!ts.isPropertyAccessExpression(callee)) return;

  const methodName = callee.name.text;
  if (!RESPONSE_SINK_METHODS.has(methodName)) return;

  const sinkLocation = locationOf(callee.name, sf, file);
  const sinkObserved = truncate(callTextOf(call, sf), 160);

  const productionGated = isInsideProductionGate(call);

  for (const arg of call.arguments) {
    classifyArgument(arg, sf, text, file, methodName, sinkLocation, sinkObserved, productionGated, facts);
  }
}

function classifyArgument(
  arg: ts.Expression,
  sf: ts.SourceFile,
  text: string,
  file: string,
  method: string,
  sinkLocation: Location,
  sinkObserved: string,
  productionGated: boolean,
  facts: ErrorLeakFact[],
): void {
  // 1. bare identifier whose name is an error carrier
  if (ts.isIdentifier(arg) && ERROR_IDENTIFIER_NAMES.has(arg.text)) {
    facts.push(buildFact(
      "error-identifier",
      sf,
      file,
      arg,
      arg.text,
      method,
      sinkLocation,
      sinkObserved,
      productionGated,
      null,
    ));
    return;
  }

  // 2. property access `<x>.stack`
  const stackAccess = findStackPropertyAccess(arg);
  if (stackAccess) {
    facts.push(buildFact(
      "stack-property",
      sf,
      file,
      stackAccess.node,
      stackAccess.text,
      method,
      sinkLocation,
      sinkObserved,
      productionGated,
      null,
    ));
    return;
  }

  // 3. JSON.stringify(error) directly as an arg
  const stringifyHit = findJsonStringifyOfError(arg);
  if (stringifyHit) {
    facts.push(buildFact(
      "json-stringify-error",
      sf,
      file,
      stringifyHit.node,
      stringifyHit.text,
      method,
      sinkLocation,
      sinkObserved,
      productionGated,
      null,
    ));
    return;
  }

  // 4. ObjectLiteralExpression containing leak
  if (ts.isObjectLiteralExpression(arg)) {
    for (const prop of arg.properties) {
      const sanitiserName = findSanitiserOnProperty(prop);
      // 4a. SpreadAssignment of an error
      if (ts.isSpreadAssignment(prop) && ts.isIdentifier(prop.expression) && ERROR_IDENTIFIER_NAMES.has(prop.expression.text)) {
        facts.push(buildFact(
          "spread-error",
          sf,
          file,
          prop.expression,
          `...${prop.expression.text}`,
          method,
          sinkLocation,
          sinkObserved,
          productionGated,
          sanitiserName,
        ));
        continue;
      }
      // 4b. PropertyAssignment whose initializer is an error / .stack / JSON.stringify(err)
      if (ts.isPropertyAssignment(prop)) {
        const init = prop.initializer;
        if (ts.isIdentifier(init) && ERROR_IDENTIFIER_NAMES.has(init.text) && !sanitiserName) {
          facts.push(buildFact(
            "error-identifier",
            sf,
            file,
            init,
            init.text,
            method,
            sinkLocation,
            sinkObserved,
            productionGated,
            sanitiserName,
          ));
          continue;
        }
        const stack = findStackPropertyAccess(init);
        if (stack && !sanitiserName) {
          facts.push(buildFact(
            "stack-property",
            sf,
            file,
            stack.node,
            stack.text,
            method,
            sinkLocation,
            sinkObserved,
            productionGated,
            sanitiserName,
          ));
          continue;
        }
        const stringify = findJsonStringifyOfError(init);
        if (stringify && !sanitiserName) {
          facts.push(buildFact(
            "json-stringify-error",
            sf,
            file,
            stringify.node,
            stringify.text,
            method,
            sinkLocation,
            sinkObserved,
            productionGated,
            sanitiserName,
          ));
          continue;
        }
      }
      // 4c. ShorthandPropertyAssignment whose name is an error carrier
      if (ts.isShorthandPropertyAssignment(prop) && ERROR_IDENTIFIER_NAMES.has(prop.name.text)) {
        facts.push(buildFact(
          "error-identifier",
          sf,
          file,
          prop.name,
          prop.name.text,
          method,
          sinkLocation,
          sinkObserved,
          productionGated,
          null,
        ));
      }
    }
  }
}

function findStackPropertyAccess(node: ts.Node): { node: ts.Node; text: string } | null {
  if (ts.isPropertyAccessExpression(node)) {
    if (SENSITIVE_ERROR_PROPERTIES.has(node.name.text)) {
      return { node, text: node.getText() };
    }
  }
  return null;
}

function findJsonStringifyOfError(node: ts.Node): { node: ts.Node; text: string } | null {
  if (!ts.isCallExpression(node)) return null;
  const callee = node.expression;
  if (!ts.isPropertyAccessExpression(callee)) return null;
  if (callee.name.text !== "stringify") return null;
  if (!(ts.isIdentifier(callee.expression) && callee.expression.text === "JSON")) return null;
  if (node.arguments.length === 0) return null;
  const first = node.arguments[0];
  if (ts.isIdentifier(first) && ERROR_IDENTIFIER_NAMES.has(first.text)) {
    return { node, text: node.getText() };
  }
  // Also catches JSON.stringify(err.stack) — same leak shape
  const stack = findStackPropertyAccess(first);
  if (stack) return { node, text: node.getText() };
  return null;
}

function findSanitiserOnProperty(prop: ts.ObjectLiteralElementLike): string | null {
  if (!ts.isPropertyAssignment(prop)) return null;
  const init = prop.initializer;
  if (!ts.isCallExpression(init)) return null;
  const callee = init.expression;
  if (ts.isIdentifier(callee) && CHARTER_ERROR_SANITISERS.has(callee.text)) {
    return callee.text;
  }
  if (ts.isPropertyAccessExpression(callee) && CHARTER_ERROR_SANITISERS.has(callee.name.text)) {
    return callee.name.text;
  }
  return null;
}

function isInsideProductionGate(node: ts.Node): boolean {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (ts.isIfStatement(cur)) {
      const condText = cur.expression.getText();
      for (const marker of PRODUCTION_GATE_MARKERS) {
        if (condText.includes(marker)) return true;
      }
    }
    cur = cur.parent;
  }
  return false;
}

// ─── Python line-wise fallback ────────────────────────────────────────────

function collectPythonFacts(text: string, file: string, facts: ErrorLeakFact[]): void {
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const line = i + 1;
    for (const callName of PYTHON_TRACEBACK_CALLS) {
      const needle = `traceback.${callName}(`;
      const idx = raw.indexOf(needle);
      if (idx < 0) continue;
      // Detect a response context on the same line — return jsonify(...), raise HTTPException(detail=...), etc.
      if (!looksLikeResponseLine(raw)) continue;
      const sourceLocation: Location = { kind: "source", file, line, col: idx + 1 };
      const sinkLocation: Location = { kind: "source", file, line };
      facts.push({
        kind: "python-traceback",
        sinkLocation,
        sinkObserved: truncate(raw.trim(), 160),
        sinkMethod: "python-response",
        sourceLocation,
        sourceObserved: truncate(needle + "...)", 160),
        productionGated: false,
        sanitised: false,
        sanitiserName: null,
      });
      break;
    }
  }
}

function looksLikeResponseLine(line: string): boolean {
  return (
    line.includes("jsonify(") ||
    line.includes("HTTPException") ||
    line.includes("Response(") ||
    line.includes("return ") ||
    line.includes("raise ")
  );
}

// ─── Test-file shape detection ────────────────────────────────────────────

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

// ─── Helpers ──────────────────────────────────────────────────────────────

function buildFact(
  kind: ErrorLeakKind,
  sf: ts.SourceFile,
  file: string,
  sourceNode: ts.Node,
  sourceText: string,
  method: string,
  sinkLocation: Location,
  sinkObserved: string,
  productionGated: boolean,
  sanitiserName: string | null,
): ErrorLeakFact {
  return {
    kind,
    sinkLocation,
    sinkObserved,
    sinkMethod: method,
    sourceLocation: locationOf(sourceNode, sf, file),
    sourceObserved: truncate(sourceText, 160),
    productionGated,
    sanitised: sanitiserName !== null,
    sanitiserName,
  };
}

function locationOf(node: ts.Node, sf: ts.SourceFile, file: string): Location {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return { kind: "source", file, line: line + 1, col: character + 1 };
}

function callTextOf(call: ts.CallExpression, sf: ts.SourceFile): string {
  return call.getText(sf);
}

function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}
