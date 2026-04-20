/**
 * K4 AST walker — source-code surface.
 *
 * Split out of `gather.ts` for file-size discipline. Consumes a single
 * source file and returns structured FileEvidence: destructive call sites
 * with their ancestor-chain guard evidence, plus a structural decision on
 * whether the file is a test file (rule must not fire inside tests).
 *
 * Zero regex. Zero string-literal arrays > 5.
 */

import ts from "typescript";
import type { Location } from "../../location.js";
import {
  GUARD_CALL_IDENTIFIERS,
  GUARD_CONDITION_IDENTIFIERS,
  GUARD_RECEIVER_METHODS,
} from "./data/confirmation-tokens.js";
import { TEST_RUNNER_MODULES, TEST_TOPLEVEL_FUNCTIONS } from "./data/test-signals.js";
import {
  classifyName,
  type DestructiveCallSite,
  type FileEvidence,
  type GuardEvidence,
} from "./gather.js";

const GUARD_CALL_SET: ReadonlySet<string> = new Set(Object.keys(GUARD_CALL_IDENTIFIERS));
const GUARD_CONDITION_SET: ReadonlySet<string> = new Set(Object.keys(GUARD_CONDITION_IDENTIFIERS));
const TEST_RUNNER_MODULE_SET: ReadonlySet<string> = new Set(Object.keys(TEST_RUNNER_MODULES));
const TEST_TOPLEVEL_SET: ReadonlySet<string> = new Set(Object.keys(TEST_TOPLEVEL_FUNCTIONS));

/**
 * Walk a single file's AST, returning destructive call sites with guard
 * evidence, and a structural is-this-a-test-file decision.
 */
export function gatherFile(file: string, text: string): FileEvidence {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const isTestFile = detectTestFileStructurally(sf);

  const callSites: DestructiveCallSite[] = [];
  if (!isTestFile) {
    ts.forEachChild(sf, function visit(node) {
      if (ts.isCallExpression(node)) {
        const site = inspectCall(node, sf, file);
        if (site) callSites.push(site);
      }
      ts.forEachChild(node, visit);
    });
  }

  return { file, callSites, isTestFile };
}

// ─── Test-file structural detection ────────────────────────────────────────

/**
 * Two-signal test-file detection:
 *
 *   Signal A — at least one top-level CallExpression to a bare identifier
 *              in TEST_TOPLEVEL_FUNCTIONS whose 2nd argument is a
 *              function expression or arrow function body.
 *
 *   Signal B — at least one of:
 *        (i) import/require from a module in TEST_RUNNER_MODULES;
 *        (ii) ≥2 top-level test-runner calls;
 *        (iii) the top-level call's callback body contains nested
 *              test-runner CallExpressions.
 *
 * File is a test file iff (A AND B). Pure AST — never inspects the
 * filename. The charter acknowledges a limited false-negative window: a
 * determined attacker can camouflage production logic behind a
 * top-level describe() wrapper AND import a runner module they do not
 * actually use.
 */
function detectTestFileStructurally(sf: ts.SourceFile): boolean {
  let topLevelRunnerCalls = 0;
  let hasCallbackNesting = false;
  let hasRunnerImport = false;

  for (const stmt of sf.statements) {
    if (isRunnerImport(stmt)) hasRunnerImport = true;
    if (isRunnerRequireStatement(stmt)) hasRunnerImport = true;
    if (isTopLevelRunnerCall(stmt)) {
      topLevelRunnerCalls++;
      if (callbackContainsNestedRunnerCall(stmt as ts.ExpressionStatement)) {
        hasCallbackNesting = true;
      }
    }
  }

  const signalA = topLevelRunnerCalls > 0;
  const signalB = hasRunnerImport || topLevelRunnerCalls >= 2 || hasCallbackNesting;
  return signalA && signalB;
}

function isRunnerImport(stmt: ts.Statement): boolean {
  if (!ts.isImportDeclaration(stmt)) return false;
  if (!ts.isStringLiteral(stmt.moduleSpecifier)) return false;
  return TEST_RUNNER_MODULE_SET.has(stmt.moduleSpecifier.text);
}

function isRunnerRequireStatement(stmt: ts.Statement): boolean {
  if (!ts.isVariableStatement(stmt)) return false;
  for (const decl of stmt.declarationList.declarations) {
    if (!decl.initializer || !ts.isCallExpression(decl.initializer)) continue;
    if (!ts.isIdentifier(decl.initializer.expression)) continue;
    if (decl.initializer.expression.text !== "require") continue;
    const arg = decl.initializer.arguments[0];
    if (arg && ts.isStringLiteral(arg) && TEST_RUNNER_MODULE_SET.has(arg.text)) return true;
  }
  return false;
}

function isTopLevelRunnerCall(stmt: ts.Statement): boolean {
  if (!ts.isExpressionStatement(stmt)) return false;
  const expr = stmt.expression;
  if (!ts.isCallExpression(expr)) return false;
  if (!ts.isIdentifier(expr.expression)) return false;
  if (!TEST_TOPLEVEL_SET.has(expr.expression.text)) return false;
  // Must have a callback-shaped argument (arrow, function expr, or async variant).
  for (const arg of expr.arguments) {
    if (ts.isArrowFunction(arg) || ts.isFunctionExpression(arg)) return true;
  }
  return false;
}

function callbackContainsNestedRunnerCall(stmt: ts.ExpressionStatement): boolean {
  const call = stmt.expression as ts.CallExpression;
  for (const arg of call.arguments) {
    if (ts.isArrowFunction(arg) || ts.isFunctionExpression(arg)) {
      if (bodyContainsRunnerCall(arg.body)) return true;
    }
  }
  return false;
}

function bodyContainsRunnerCall(body: ts.ConciseBody): boolean {
  let found = false;
  function visit(node: ts.Node): void {
    if (found) return;
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
      if (TEST_TOPLEVEL_SET.has(node.expression.text)) {
        found = true;
        return;
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(body);
  return found;
}

// ─── Destructive-call inspection ───────────────────────────────────────────

function inspectCall(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  file: string,
): DestructiveCallSite | null {
  const symbol = extractCallSymbol(call);
  if (!symbol) return null;

  const classification = classifyName(symbol);
  if (!classification.destructive) return null;

  const location = sourceLocation(sf, file, call);
  const observed = lineTextAt(sf, call.getStart(sf)).trim().slice(0, 200);

  const guard = walkAncestorsForGuard(call);

  return {
    location,
    callSymbol: classification,
    observed,
    guard,
    inTestFile: false, // caller only invokes us for non-test files
    file,
  };
}

/**
 * Extract the symbol identifying WHICH function is being called. For
 * `foo.bar.baz(args)` the relevant symbol is `baz`. For `foo(args)` it's
 * `foo`. For `obj["dynamic"](args)` we return null — we don't analyse
 * string-indexed calls (would enable bypasses and we acknowledge that in
 * the charter).
 */
function extractCallSymbol(call: ts.CallExpression): string | null {
  const expr = call.expression;
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr)) return expr.name.text;
  if (ts.isParenthesizedExpression(expr)) {
    // `(foo.bar)(args)` — unwrap and recurse conceptually.
    const inner = expr.expression;
    if (ts.isIdentifier(inner)) return inner.text;
    if (ts.isPropertyAccessExpression(inner)) return inner.name.text;
  }
  return null;
}

// ─── Ancestor-chain guard walk ─────────────────────────────────────────────

/**
 * Walk from the destructive call upward, collecting any guard evidence on
 * the path. A guard COUNTS if the call is inside the IfStatement's
 * thenStatement (the guarded branch) — an IfStatement whose condition
 * merely APPEARS in the ancestor chain without the call being on its
 * positive branch is not a guard.
 *
 * Guard forms recognised:
 *
 *   - IfStatement condition references a GUARD_CONDITION_IDENTIFIERS identifier
 *   - IfStatement condition contains a call to a GUARD_CALL_IDENTIFIERS identifier
 *   - IfStatement condition contains a receiver.method call matching
 *     GUARD_RECEIVER_METHODS (e.g. window.confirm())
 *   - Direct sibling `await confirm(...)` / `confirm()` statement preceding
 *     the destructive call in the same block (early-confirmation pattern)
 */
function walkAncestorsForGuard(call: ts.Node): GuardEvidence {
  const out: GuardEvidence = {
    conditionIdentifiers: [],
    guardCalls: [],
    guardReceiverMethods: [],
    guardLocation: null,
  };

  let current: ts.Node | undefined = call.parent;
  let child: ts.Node = call;

  while (current) {
    if (ts.isIfStatement(current)) {
      // Only count as a guard if `child` sits inside current.thenStatement.
      if (nodeEncloses(current.thenStatement, child)) {
        collectGuardEvidenceFromCondition(current.expression, current, out);
      }
    }

    // Early-confirmation pattern: preceding sibling in a Block that is a
    // confirmation call — counts as a guard ONLY when followed by a
    // control-flow gate (return/throw) on the same path. For the simplest
    // case we detect a sibling ExpressionStatement of `confirm()` /
    // `approve()` / etc. immediately before the destructive call.
    if (ts.isBlock(current) || ts.isSourceFile(current)) {
      inspectPrecedingSiblingConfirmations(current, child, out);
    }

    if (out.guardLocation !== null) return out;

    child = current;
    current = current.parent;
  }

  return out;
}

function nodeEncloses(outer: ts.Node, inner: ts.Node): boolean {
  let n: ts.Node | undefined = inner;
  while (n) {
    if (n === outer) return true;
    n = n.parent;
  }
  return false;
}

function collectGuardEvidenceFromCondition(
  expr: ts.Expression,
  ifStmt: ts.IfStatement,
  out: GuardEvidence,
): void {
  visitCondition(expr, out);
  if (
    out.conditionIdentifiers.length > 0 ||
    out.guardCalls.length > 0 ||
    out.guardReceiverMethods.length > 0
  ) {
    const sf = ifStmt.getSourceFile();
    const start = sf.getLineAndCharacterOfPosition(ifStmt.getStart(sf));
    out.guardLocation = {
      kind: "source",
      file: sf.fileName,
      line: start.line + 1,
      col: start.character + 1,
    };
  }
}

function visitCondition(node: ts.Node, out: GuardEvidence): void {
  if (ts.isIdentifier(node)) {
    if (GUARD_CONDITION_SET.has(node.text)) {
      if (!out.conditionIdentifiers.includes(node.text)) {
        out.conditionIdentifiers.push(node.text);
      }
    }
  }
  if (ts.isCallExpression(node)) {
    if (ts.isIdentifier(node.expression)) {
      if (GUARD_CALL_SET.has(node.expression.text)) {
        if (!out.guardCalls.includes(node.expression.text)) {
          out.guardCalls.push(node.expression.text);
        }
      }
    } else if (ts.isPropertyAccessExpression(node.expression)) {
      const recvNode = node.expression.expression;
      const method = node.expression.name.text;
      if (ts.isIdentifier(recvNode)) {
        const methods = GUARD_RECEIVER_METHODS[recvNode.text];
        if (methods && methods[method] === true) {
          const label = `${recvNode.text}.${method}`;
          if (!out.guardReceiverMethods.includes(label)) {
            out.guardReceiverMethods.push(label);
          }
        }
      }
    }
  }
  ts.forEachChild(node, (c) => visitCondition(c, out));
}

/**
 * Walk the preceding statements in a Block / SourceFile looking for
 * `await confirm(...)` / `confirm()` directly before the destructive
 * call's enclosing statement. The intent is to honour the pattern
 *
 *     const ok = await confirm("…");
 *     if (!ok) return;
 *     deleteAll();
 *
 * where the `if (!ok) return` is handled by the IfStatement walker (its
 * condition `ok` is a GUARD_CONDITION_IDENTIFIERS entry if the developer
 * named the variable from the approved list — in practice we recognise
 * the preceding confirmation CALL directly instead, which is the signal
 * regulators actually want to see.
 */
function inspectPrecedingSiblingConfirmations(
  block: ts.Block | ts.SourceFile,
  child: ts.Node,
  out: GuardEvidence,
): void {
  const stmts = block.statements;
  const childStmtIndex = stmts.indexOf(child as ts.Statement);
  if (childStmtIndex <= 0) return;
  for (let i = 0; i < childStmtIndex; i++) {
    const s = stmts[i];
    const callId = extractStatementConfirmationCall(s);
    if (callId !== null) {
      if (!out.guardCalls.includes(callId)) out.guardCalls.push(callId);
      const sf = s.getSourceFile();
      const start = sf.getLineAndCharacterOfPosition(s.getStart(sf));
      out.guardLocation = {
        kind: "source",
        file: sf.fileName,
        line: start.line + 1,
        col: start.character + 1,
      };
      return;
    }
  }
}

function extractStatementConfirmationCall(stmt: ts.Statement): string | null {
  // `await confirm(...)` / `confirm()` / `const ok = await confirm(...)`
  if (ts.isExpressionStatement(stmt)) {
    return extractConfirmationCallFromExpression(stmt.expression);
  }
  if (ts.isVariableStatement(stmt)) {
    for (const decl of stmt.declarationList.declarations) {
      if (!decl.initializer) continue;
      const id = extractConfirmationCallFromExpression(decl.initializer);
      if (id) return id;
    }
  }
  return null;
}

function extractConfirmationCallFromExpression(expr: ts.Expression): string | null {
  let node: ts.Expression = expr;
  if (ts.isAwaitExpression(node)) node = node.expression;
  if (ts.isParenthesizedExpression(node)) node = node.expression;
  if (!ts.isCallExpression(node)) return null;
  if (ts.isIdentifier(node.expression) && GUARD_CALL_SET.has(node.expression.text)) {
    return node.expression.text;
  }
  if (ts.isPropertyAccessExpression(node.expression) && ts.isIdentifier(node.expression.expression)) {
    const recv = node.expression.expression.text;
    const method = node.expression.name.text;
    const methods = GUARD_RECEIVER_METHODS[recv];
    if (methods && methods[method] === true) return `${recv}.${method}`;
  }
  return null;
}

// ─── Location helpers ──────────────────────────────────────────────────────

function sourceLocation(sf: ts.SourceFile, file: string, node: ts.Node): Location {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return { kind: "source", file, line: line + 1, col: character + 1 };
}

function lineTextAt(sf: ts.SourceFile, pos: number): string {
  const { line } = sf.getLineAndCharacterOfPosition(pos);
  const lines = sf.text.split("\n");
  return lines[line] ?? "";
}
