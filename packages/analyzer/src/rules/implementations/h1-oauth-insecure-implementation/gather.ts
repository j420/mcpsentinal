/**
 * H1 OAuth evidence gathering — deterministic TypeScript AST walk.
 *
 * The threat researcher's charter (CHARTER.md) specifies six patterns.
 * This file is the engineer's translation into structural queries over
 * the TypeScript AST. It does NOT construct evidence chains —
 * `index.ts` consumes the gathered hits and builds the chain.
 *
 * No regex literals, no string-literal arrays > 5. All vocabulary is
 * loaded from `./data/*.ts` as typed Records.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  H1_OAUTH_VIOLATION_PATTERNS,
  type OAuthPatternEntry,
  type PatternId,
} from "./data/oauth-patterns.js";
import {
  REQUEST_TAINT_RECEIVERS,
  REQUEST_TAINT_MEMBERS,
  REDIRECT_URI_PROPS,
  SCOPE_PROPS,
  RESPONSE_TYPE_PROPS,
  GRANT_TYPE_PROPS,
  TOKEN_KEY_HINTS,
  STATE_PROPS,
  CODE_PROPS,
} from "./data/oauth-tokens.js";

const SYNTHETIC_FILE = "<source>";
const TEST_FILE_SUFFIX_1 = ".test.ts";
const TEST_FILE_SUFFIX_2 = ".spec.ts";
const TEST_FILE_SUFFIX_3 = "__tests__";
const TEST_FILE_SUFFIX_4 = "__fixtures__";

/** One hit per matched OAuth pattern. */
export interface H1Hit {
  /** Which pattern was matched. */
  pattern: PatternId;
  /** The full pattern entry (rationale, confidence, cite). */
  entry: OAuthPatternEntry;
  /** AST position of the offending node. */
  location: Location;
  /** Text of the offending expression (trimmed, length-capped). */
  observed: string;
  /** Source-kind location of the tainted source (for request-sourced patterns). */
  sourceLocation?: Location;
  /** Observed tainted source expression (for request-sourced patterns). */
  sourceObserved?: string;
}

export interface H1Gathered {
  mode: "absent" | "facts";
  hits: H1Hit[];
}

export function gatherH1(context: AnalysisContext): H1Gathered {
  if (!context.source_code || isTestPath(context.source_code)) {
    return { mode: "absent", hits: [] };
  }

  const files = collectFiles(context);
  const hits: H1Hit[] = [];

  for (const [file, text] of files) {
    if (isTestPath(file)) continue;
    hits.push(...scanFile(file, text));
  }

  return {
    mode: hits.length > 0 ? "facts" : "absent",
    hits,
  };
}

// ─── File collection ──────────────────────────────────────────────────────

function collectFiles(context: AnalysisContext): Map<string, string> {
  const files = new Map<string, string>();
  if (context.source_files && context.source_files.size > 0) {
    for (const [k, v] of context.source_files) files.set(k, v);
  } else if (context.source_code) {
    files.set(SYNTHETIC_FILE, context.source_code);
  }
  return files;
}

function isTestPath(pathOrText: string): boolean {
  return (
    pathOrText.includes(TEST_FILE_SUFFIX_1) ||
    pathOrText.includes(TEST_FILE_SUFFIX_2) ||
    pathOrText.includes(TEST_FILE_SUFFIX_3) ||
    pathOrText.includes(TEST_FILE_SUFFIX_4)
  );
}

// ─── AST scan ──────────────────────────────────────────────────────────────

function scanFile(file: string, text: string): H1Hit[] {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const hits: H1Hit[] = [];

  // Handler-scope walker: track the currently-entered handler/function body
  // so the state-validation-absence check knows the scope to confirm absence
  // within.
  let insideHandler = false;
  let handlerReadsCode = false;
  let handlerReadsState = false;
  let handlerCompareState = false;
  let handlerStart: ts.Node | null = null;

  ts.forEachChild(sf, function visit(node) {
    // 1. Implicit-flow / ROPC literal: property assignments with fixed literals.
    collectLiteralPatterns(node, sf, file, hits);

    // 2. redirect_uri / scope assignments whose RHS is a request-tainted expr.
    collectTaintedAssignments(node, sf, file, hits);

    // 3. localStorage.setItem(token-key, ...) or sessionStorage equivalent.
    collectLocalStorageTokenWrite(node, sf, file, hits);

    // 4. state-validation-absence — analyse handler scopes.
    if (isHandlerBoundary(node)) {
      const previous = {
        insideHandler,
        handlerReadsCode,
        handlerReadsState,
        handlerCompareState,
        handlerStart,
      };
      insideHandler = true;
      handlerReadsCode = false;
      handlerReadsState = false;
      handlerCompareState = false;
      handlerStart = node;

      ts.forEachChild(node, visit);

      if (handlerReadsCode && (!handlerReadsState || !handlerCompareState)) {
        const startPos = node.getStart(sf);
        const start = toLine(sf, startPos);
        hits.push({
          pattern: "state-validation-absence",
          entry: H1_OAUTH_VIOLATION_PATTERNS["state-validation-absence"],
          location: { kind: "source", file, line: start.line, col: start.col },
          observed:
            text
              .split("\n")
              .slice(start.line - 1, start.line + 4)
              .join("\n")
              .trim()
              .slice(0, 200),
        });
      }

      insideHandler = previous.insideHandler;
      handlerReadsCode = previous.handlerReadsCode;
      handlerReadsState = previous.handlerReadsState;
      handlerCompareState = previous.handlerCompareState;
      handlerStart = previous.handlerStart;
      return;
    }

    if (insideHandler) {
      if (isPropertyRead(node, CODE_PROPS)) handlerReadsCode = true;
      if (isPropertyRead(node, STATE_PROPS)) handlerReadsState = true;
      if (isStateComparison(node)) handlerCompareState = true;
    }

    ts.forEachChild(node, visit);
  });

  return hits;
}

// ─── Pattern collectors ────────────────────────────────────────────────────

/** response_type="token", grant_type="password" (property assignments or object-literal keys). */
function collectLiteralPatterns(
  node: ts.Node,
  sf: ts.SourceFile,
  file: string,
  hits: H1Hit[],
): void {
  // Property assignment inside an object literal: `{ response_type: "token" }`.
  if (ts.isPropertyAssignment(node)) {
    const keyName = propertyKeyName(node.name);
    if (keyName && RESPONSE_TYPE_PROPS[keyName] !== undefined) {
      if (
        ts.isStringLiteral(node.initializer) &&
        node.initializer.text === "token"
      ) {
        hits.push(
          makeHit("implicit-flow-literal", node, sf, file, node.getText(sf)),
        );
      }
    }
    if (keyName && GRANT_TYPE_PROPS[keyName] !== undefined) {
      if (
        ts.isStringLiteral(node.initializer) &&
        node.initializer.text === "password"
      ) {
        hits.push(
          makeHit("ropc-grant-literal", node, sf, file, node.getText(sf)),
        );
      }
    }
  }

  // BinaryExpression assignment: `response_type = "token"` or `x.response_type = "token"`.
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
    const lhs = node.left;
    const keyName = assignmentLhsKey(lhs);
    if (keyName && RESPONSE_TYPE_PROPS[keyName] !== undefined) {
      if (ts.isStringLiteral(node.right) && node.right.text === "token") {
        hits.push(
          makeHit("implicit-flow-literal", node, sf, file, node.getText(sf)),
        );
      }
    }
    if (keyName && GRANT_TYPE_PROPS[keyName] !== undefined) {
      if (ts.isStringLiteral(node.right) && node.right.text === "password") {
        hits.push(
          makeHit("ropc-grant-literal", node, sf, file, node.getText(sf)),
        );
      }
    }
  }

  // VariableDeclaration: `const response_type = "token"` or `const grant_type = "password"`.
  if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
    const keyName = node.name.text;
    if (RESPONSE_TYPE_PROPS[keyName] !== undefined) {
      if (ts.isStringLiteral(node.initializer) && node.initializer.text === "token") {
        hits.push(
          makeHit("implicit-flow-literal", node, sf, file, node.getText(sf)),
        );
      }
    }
    if (GRANT_TYPE_PROPS[keyName] !== undefined) {
      if (ts.isStringLiteral(node.initializer) && node.initializer.text === "password") {
        hits.push(
          makeHit("ropc-grant-literal", node, sf, file, node.getText(sf)),
        );
      }
    }
  }
}

/** redirect_uri = req.query.foo, scope = req.body.scope, etc. */
function collectTaintedAssignments(
  node: ts.Node,
  sf: ts.SourceFile,
  file: string,
  hits: H1Hit[],
): void {
  const inspect = (lhsKey: string | null, rhs: ts.Node, carrier: ts.Node): void => {
    if (lhsKey === null) return;
    const taint = identifyRequestTaint(rhs);
    if (taint === null) return;
    if (REDIRECT_URI_PROPS[lhsKey] !== undefined) {
      hits.push({
        pattern: "redirect-uri-from-request",
        entry: H1_OAUTH_VIOLATION_PATTERNS["redirect-uri-from-request"],
        location: sourceLocation(sf, file, carrier),
        observed: carrier.getText(sf).slice(0, 200),
        sourceLocation: sourceLocation(sf, file, rhs),
        sourceObserved: rhs.getText(sf).slice(0, 120),
      });
    }
    if (SCOPE_PROPS[lhsKey] !== undefined) {
      hits.push({
        pattern: "scope-from-request",
        entry: H1_OAUTH_VIOLATION_PATTERNS["scope-from-request"],
        location: sourceLocation(sf, file, carrier),
        observed: carrier.getText(sf).slice(0, 200),
        sourceLocation: sourceLocation(sf, file, rhs),
        sourceObserved: rhs.getText(sf).slice(0, 120),
      });
    }
  };

  if (ts.isPropertyAssignment(node)) {
    const key = propertyKeyName(node.name);
    inspect(key, node.initializer, node);
  }
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
    const lhs = node.left;
    const key = assignmentLhsKey(lhs);
    inspect(key, node.right, node);
  }
  if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
    inspect(node.name.text, node.initializer, node);
  }
}

/** localStorage.setItem("access_token", token) / sessionStorage. */
function collectLocalStorageTokenWrite(
  node: ts.Node,
  sf: ts.SourceFile,
  file: string,
  hits: H1Hit[],
): void {
  if (!ts.isCallExpression(node)) return;
  const callee = node.expression;
  if (!ts.isPropertyAccessExpression(callee)) return;
  const recv = callee.expression;
  if (!ts.isIdentifier(recv)) return;
  const recvName = recv.text;
  if (recvName !== "localStorage" && recvName !== "sessionStorage") return;
  if (callee.name.text !== "setItem") return;
  const firstArg = node.arguments[0];
  if (!firstArg) return;
  let keyValue: string | null = null;
  if (ts.isStringLiteral(firstArg)) keyValue = firstArg.text;
  else if (ts.isNoSubstitutionTemplateLiteral(firstArg)) keyValue = firstArg.text;
  if (keyValue === null) return;
  const lowered = keyValue.toLowerCase();
  for (const token of Object.keys(TOKEN_KEY_HINTS)) {
    if (lowered.includes(token.toLowerCase())) {
      hits.push(
        makeHit("localstorage-token-write", node, sf, file, node.getText(sf)),
      );
      return;
    }
  }
}

// ─── State-validation handler-scope helpers ────────────────────────────────

function isHandlerBoundary(node: ts.Node): boolean {
  // A handler is a function whose body we want to scope the state check to.
  // We treat any FunctionDeclaration, FunctionExpression, ArrowFunction,
  // or MethodDeclaration with a body as a boundary. This over-approximates
  // but the absence-check only fires when the handler BOTH reads `code` AND
  // fails to read+compare `state` — the over-approximation is benign.
  if (ts.isFunctionDeclaration(node) && node.body !== undefined) return true;
  if (ts.isFunctionExpression(node)) return true;
  if (ts.isArrowFunction(node)) return true;
  if (ts.isMethodDeclaration(node)) return true;
  return false;
}

/** True when node is a `.<prop>` read where prop is one of the target props AND the receiver chain includes a request-like identifier. */
function isPropertyRead(
  node: ts.Node,
  props: Record<string, unknown>,
): boolean {
  if (!ts.isPropertyAccessExpression(node)) return false;
  const propName = node.name.text;
  if (props[propName] === undefined) return false;
  return receiverIsRequestLike(node.expression);
}

function receiverIsRequestLike(expr: ts.Node): boolean {
  if (ts.isIdentifier(expr)) return REQUEST_TAINT_RECEIVERS[expr.text] !== undefined;
  if (ts.isPropertyAccessExpression(expr)) {
    const inner = expr.expression;
    if (ts.isIdentifier(inner) && REQUEST_TAINT_RECEIVERS[inner.text] !== undefined) {
      if (REQUEST_TAINT_MEMBERS[expr.name.text] !== undefined) return true;
    }
    return receiverIsRequestLike(inner);
  }
  return false;
}

/** Is this node an equality comparison involving a state property read? */
function isStateComparison(node: ts.Node): boolean {
  if (!ts.isBinaryExpression(node)) return false;
  const kind = node.operatorToken.kind;
  if (
    kind !== ts.SyntaxKind.EqualsEqualsToken &&
    kind !== ts.SyntaxKind.EqualsEqualsEqualsToken &&
    kind !== ts.SyntaxKind.ExclamationEqualsToken &&
    kind !== ts.SyntaxKind.ExclamationEqualsEqualsToken
  ) {
    return false;
  }
  if (containsStateReference(node.left) && node.right !== undefined) return true;
  if (containsStateReference(node.right) && node.left !== undefined) return true;
  return false;
}

function containsStateReference(node: ts.Node): boolean {
  if (ts.isPropertyAccessExpression(node)) {
    if (STATE_PROPS[node.name.text] !== undefined) return true;
  }
  if (ts.isIdentifier(node)) {
    // Bare identifier named "state" or a STATE_PROPS key — accept as a state binding.
    if (STATE_PROPS[node.text] !== undefined) return true;
  }
  return false;
}

// ─── Tainting utilities ────────────────────────────────────────────────────

/**
 * Identify an expression that reads req.body/req.query/req.params etc.
 * Returns the node text (for observed) or null if not tainted.
 */
function identifyRequestTaint(expr: ts.Node): ts.Node | null {
  if (ts.isPropertyAccessExpression(expr)) {
    const recv = expr.expression;
    const propName = expr.name.text;
    if (ts.isIdentifier(recv) && REQUEST_TAINT_RECEIVERS[recv.text] !== undefined) {
      if (REQUEST_TAINT_MEMBERS[propName] !== undefined) return expr;
      // Also handle req.query.foo (bare req.query counts even without a sub-prop).
      return expr;
    }
    if (
      ts.isPropertyAccessExpression(recv) &&
      ts.isIdentifier(recv.expression) &&
      REQUEST_TAINT_RECEIVERS[recv.expression.text] !== undefined &&
      REQUEST_TAINT_MEMBERS[recv.name.text] !== undefined
    ) {
      return expr;
    }
  }
  if (ts.isElementAccessExpression(expr)) {
    const recv = expr.expression;
    if (ts.isIdentifier(recv) && REQUEST_TAINT_RECEIVERS[recv.text] !== undefined) {
      return expr;
    }
  }
  return null;
}

// ─── AST helpers ───────────────────────────────────────────────────────────

function propertyKeyName(name: ts.PropertyName): string | null {
  if (ts.isIdentifier(name)) return name.text;
  if (ts.isStringLiteral(name)) return name.text;
  if (ts.isNoSubstitutionTemplateLiteral(name)) return name.text;
  return null;
}

function assignmentLhsKey(lhs: ts.Node): string | null {
  if (ts.isIdentifier(lhs)) return lhs.text;
  if (ts.isPropertyAccessExpression(lhs)) return lhs.name.text;
  if (ts.isElementAccessExpression(lhs)) {
    const arg = lhs.argumentExpression;
    if (arg && ts.isStringLiteral(arg)) return arg.text;
    if (arg && ts.isNoSubstitutionTemplateLiteral(arg)) return arg.text;
  }
  return null;
}

function sourceLocation(sf: ts.SourceFile, file: string, node: ts.Node): Location {
  const start = toLine(sf, node.getStart(sf));
  return { kind: "source", file, line: start.line, col: start.col };
}

function toLine(sf: ts.SourceFile, pos: number): { line: number; col: number } {
  const { line, character } = sf.getLineAndCharacterOfPosition(pos);
  return { line: line + 1, col: character + 1 };
}

function makeHit(
  pattern: PatternId,
  node: ts.Node,
  sf: ts.SourceFile,
  file: string,
  observed: string,
): H1Hit {
  return {
    pattern,
    entry: H1_OAUTH_VIOLATION_PATTERNS[pattern],
    location: sourceLocation(sf, file, node),
    observed: observed.trim().slice(0, 200),
  };
}
