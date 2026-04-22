/**
 * O5 gather step — AST detection of BULK env-var reads.
 *
 * Zero regex. Matches four structural shapes:
 *
 *   1. Object.keys(process.env) / Object.entries(...) /
 *      Object.values(...) / Object.fromEntries(...) /
 *      JSON.stringify(process.env).
 *   2. os.environ.items() / os.environ.keys() / os.environ.values() /
 *      os.environ.copy() / dict(os.environ) — all expressible in
 *      TypeScript bindings that mirror the Python semantics.
 *   3. Object spread `{ ...process.env }` in an ObjectLiteralExpression.
 *   4. Explicit iteration over the env root without a safelist
 *      filter in the loop body — for (const k of Object.keys(process.env)).
 *
 * A single `process.env.FOO` is NOT a hit. The receiver must be
 * the env root, and the access must be bulk.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  JS_BULK_METHODS,
  PY_BULK_METHODS,
  ENV_ROOT_RECEIVERS,
  ALLOWLIST_FILTERS,
} from "./data/vocabulary.js";

const JS_BULK_SET: ReadonlySet<string> = new Set(Object.keys(JS_BULK_METHODS));
const PY_BULK_SET: ReadonlySet<string> = new Set(Object.keys(PY_BULK_METHODS));
const ALLOWLIST_SET: ReadonlySet<string> = new Set(Object.keys(ALLOWLIST_FILTERS));

export type BulkReadKind =
  | "object-keys-call"
  | "object-spread"
  | "json-stringify"
  | "py-environ-method"
  | "dict-wrapper";

export interface EnvBulkReadSite {
  kind: BulkReadKind;
  /** Expression as observed (e.g. "Object.keys(process.env)"). */
  observed: string;
  /** Which root receiver was detected (process.env / os.environ). */
  receiver: string;
  /** Source-kind Location of the bulk expression. */
  location: Location;
  /** Enclosing function location (null for top-level). */
  enclosingFunctionLocation: Location | null;
  /** Whether an allowlist filter identifier exists in the enclosing scope. */
  enclosingHasAllowlist: boolean;
  /** Matched allowlist identifier, if any. */
  matchedAllowlist: string | null;
}

export interface O5Gathered {
  sites: EnvBulkReadSite[];
  isTestFile: boolean;
}

export function gatherO5(context: AnalysisContext): O5Gathered {
  const text = context.source_code;
  if (!text) return { sites: [], isTestFile: false };

  const sf = ts.createSourceFile(
    "<concatenated-source>",
    text,
    ts.ScriptTarget.Latest,
    true,
  );

  if (detectTestFileStructurally(sf)) return { sites: [], isTestFile: true };

  const sites: EnvBulkReadSite[] = [];

  ts.forEachChild(sf, function visit(node) {
    if (ts.isCallExpression(node)) {
      const hit = classifyCall(node);
      if (hit) recordSite(node, sf, hit, sites);
    }
    if (ts.isObjectLiteralExpression(node)) {
      for (const prop of node.properties) {
        if (ts.isSpreadAssignment(prop)) {
          const recv = expressionPath(prop.expression);
          if (recv && ENV_ROOT_RECEIVERS[recv]) {
            recordSite(
              prop,
              sf,
              { kind: "object-spread", receiver: recv, observed: `{...${recv}}` },
              sites,
            );
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  });

  return { sites, isTestFile: false };
}

function classifyCall(
  call: ts.CallExpression,
): { kind: BulkReadKind; receiver: string; observed: string } | null {
  if (!ts.isPropertyAccessExpression(call.expression)) {
    // Bare-identifier call: dict(os.environ)
    if (ts.isIdentifier(call.expression) && call.expression.text === "dict") {
      const arg = call.arguments[0];
      if (arg) {
        const argPath = expressionPath(arg);
        if (argPath && ENV_ROOT_RECEIVERS[argPath]) {
          return { kind: "dict-wrapper", receiver: argPath, observed: `dict(${argPath})` };
        }
      }
    }
    return null;
  }
  const method = call.expression.name.text.toLowerCase();
  const recvExpr = call.expression.expression;

  // Case 1: Object.<method>(process.env) or JSON.stringify(process.env)
  if (ts.isIdentifier(recvExpr)) {
    const recvName = recvExpr.text;
    if (recvName === "Object" && JS_BULK_SET.has(method) && method !== "stringify") {
      const argPath = call.arguments[0] ? expressionPath(call.arguments[0]) : null;
      if (argPath && ENV_ROOT_RECEIVERS[argPath]) {
        return {
          kind: "object-keys-call",
          receiver: argPath,
          observed: `Object.${call.expression.name.text}(${argPath})`,
        };
      }
    }
    if (recvName === "JSON" && method === "stringify") {
      const argPath = call.arguments[0] ? expressionPath(call.arguments[0]) : null;
      if (argPath && ENV_ROOT_RECEIVERS[argPath]) {
        return {
          kind: "json-stringify",
          receiver: argPath,
          observed: `JSON.stringify(${argPath})`,
        };
      }
    }
  }

  // Case 2: os.environ.items() / os.environ.keys() / environ.items()
  const recvPath = expressionPath(recvExpr);
  if (recvPath && ENV_ROOT_RECEIVERS[recvPath] && PY_BULK_SET.has(method)) {
    return {
      kind: "py-environ-method",
      receiver: recvPath,
      observed: `${recvPath}.${call.expression.name.text}()`,
    };
  }

  return null;
}

/**
 * Render the dotted identifier path of an expression, or null if
 * the expression is not a pure PropertyAccess chain of identifiers.
 *   process.env       → "process.env"
 *   os.environ        → "os.environ"
 *   environ           → "environ"
 *   foo.bar.baz       → "foo.bar.baz"
 *   anything else     → null
 */
function expressionPath(expr: ts.Expression): string | null {
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr)) {
    const head = expressionPath(expr.expression);
    if (head === null) return null;
    return `${head}.${expr.name.text}`;
  }
  return null;
}

function recordSite(
  node: ts.Node,
  sf: ts.SourceFile,
  hit: { kind: BulkReadKind; receiver: string; observed: string },
  out: EnvBulkReadSite[],
): void {
  const enclosing = findEnclosingFunction(node);
  const enclosingLoc = enclosing ? sourceLocation(sf, enclosing) : null;
  const allowlist = enclosing ? findAllowlistInScope(enclosing) : null;
  out.push({
    kind: hit.kind,
    receiver: hit.receiver,
    observed: hit.observed,
    location: sourceLocation(sf, node),
    enclosingFunctionLocation: enclosingLoc,
    enclosingHasAllowlist: allowlist !== null,
    matchedAllowlist: allowlist,
  });
}

function findAllowlistInScope(enclosing: ts.Node): string | null {
  let found: string | null = null;
  function visit(n: ts.Node): void {
    if (found) return;
    if (ts.isIdentifier(n) && ALLOWLIST_SET.has(n.text)) {
      found = n.text;
      return;
    }
    ts.forEachChild(n, visit);
  }
  ts.forEachChild(enclosing, visit);
  return found;
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

const TEST_RUNNER_MODULES: ReadonlySet<string> = new Set([
  "vitest",
  "mocha",
  "jest",
  "node:test",
  "tap",
]);

const TEST_TOPLEVEL: ReadonlySet<string> = new Set([
  "describe",
  "it",
  "test",
  "suite",
  "specify",
]);

function detectTestFileStructurally(sf: ts.SourceFile): boolean {
  let topLevelItOrTest = 0;
  let topLevelRunnerCalls = 0;
  let hasRunnerImport = false;
  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)) {
      if (TEST_RUNNER_MODULES.has(stmt.moduleSpecifier.text)) hasRunnerImport = true;
    }
    if (ts.isExpressionStatement(stmt) && ts.isCallExpression(stmt.expression)) {
      const callee = stmt.expression.expression;
      if (ts.isIdentifier(callee) && TEST_TOPLEVEL.has(callee.text)) {
        topLevelRunnerCalls++;
        if (callee.text === "it" || callee.text === "test") topLevelItOrTest++;
      }
    }
  }
  if (topLevelItOrTest > 0) return true;
  return topLevelRunnerCalls > 0 && (hasRunnerImport || topLevelRunnerCalls >= 2);
}

function sourceLocation(sf: ts.SourceFile, node: ts.Node): Location {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return {
    kind: "source",
    file: sf.fileName,
    line: line + 1,
    col: character + 1,
  };
}
