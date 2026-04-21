/**
 * K16 AST walker — call-graph construction + SCC detection + per-function
 * guard / cycle-breaker analysis. Zero regex.
 *
 * Algorithm:
 *   1. Collect every named function-like node in the file: FunctionDeclaration,
 *      MethodDeclaration, FunctionExpression / ArrowFunction bound to a
 *      VariableDeclaration.
 *   2. For each function, walk its body collecting outgoing edges to other
 *      known functions. Edges include:
 *        - direct CallExpression whose callee resolves to a known function;
 *        - receiver.method(stringLiteral) for tool-call receivers — a
 *          synthetic edge from the enclosing function to the function whose
 *          name equals stringLiteral (MCP recursion-via-tool-call case);
 *        - emitter-shape emit("name") — synthetic edge to function "name".
 *   3. Run Tarjan's strongly-connected-components algorithm. Any SCC of
 *      size ≥ 2 is a mutual-recursion cycle. A self-loop edge on a single
 *      node is a direct-recursion cycle.
 *   4. For every cycle, inspect the cycle's entry function for guards:
 *        - a declared parameter name in DEPTH_PARAMETER_NAMES;
 *        - a BinaryExpression body node comparing that parameter against a
 *          numeric literal or an UPPER_SNAKE identifier;
 *        - a visited-set (Set/Map/WeakSet) constructor near a .has/.add call.
 *   5. Emit a RecursionCycle for every cycle that lacks BOTH the depth
 *      comparison AND the cycle-breaker.
 */

import ts from "typescript";
import type { Location } from "../../location.js";
import type { FileEvidence, RecursionCycle, RecursionEdgeKind } from "./gather.js";
import {
  DEPTH_PARAMETER_NAMES,
  DEPTH_CONSTANT_PREFIXES,
  CYCLE_BREAKER_TYPES,
  CYCLE_BREAKER_MEMBER_METHODS,
  TOOL_CALL_RECEIVERS,
  TOOL_CALL_METHODS,
} from "./data/recursion-guards.js";

const DEPTH_PARAM_SET: ReadonlySet<string> = new Set(Object.keys(DEPTH_PARAMETER_NAMES));
const DEPTH_CONSTANT_PREFIX_LIST: readonly string[] = Object.keys(DEPTH_CONSTANT_PREFIXES);
const CYCLE_BREAKER_TYPE_SET: ReadonlySet<string> = new Set(Object.keys(CYCLE_BREAKER_TYPES));
const CYCLE_BREAKER_METHOD_SET: ReadonlySet<string> = new Set(
  Object.keys(CYCLE_BREAKER_MEMBER_METHODS),
);
const TOOL_CALL_RECEIVER_SET: ReadonlySet<string> = new Set(
  Object.keys(TOOL_CALL_RECEIVERS).map((x) => x.toLowerCase()),
);
const TOOL_CALL_METHOD_SET: ReadonlySet<string> = new Set(
  Object.keys(TOOL_CALL_METHODS).map((x) => x.toLowerCase()),
);

const TEST_RUNNER_MODULE_SET: ReadonlySet<string> = new Set([
  "vitest", "jest", "@jest/globals", "mocha", "node:test",
]);
const TEST_TOPLEVEL_SET: ReadonlySet<string> = new Set([
  "describe", "it", "test", "suite",
]);

interface FunctionNode {
  name: string;
  /** The function-like AST node (body holder). */
  node: ts.Node;
  /** The header line location for display (name position). */
  headerLocation: Location;
  /** The parameter names on this function (lower-cased). */
  paramNames: string[];
  /** Whether any body comparison binds a known depth parameter to a
   *  numeric literal or UPPER_SNAKE constant. */
  hasDepthComparison: boolean;
  /** Whether the body instantiates a visited-set and performs .has/.add on it. */
  hasCycleBreaker: boolean;
  /** Observed entry text (header line, trimmed). */
  observedEntry: string;
}

interface RecursionEdge {
  fromIndex: number;
  toIndex: number;
  kind: RecursionEdgeKind;
  callNode: ts.Node;
}

export function gatherFile(file: string, text: string): FileEvidence {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const isTestFile = detectTestFileStructurally(sf);
  if (isTestFile) {
    return { file, cycles: [], isTestFile: true };
  }

  const functions = collectFunctions(sf, file);
  if (functions.length === 0) {
    return { file, cycles: [], isTestFile: false };
  }

  // Resolve per-function guard signals (AST body walk).
  for (const fn of functions) {
    fn.hasDepthComparison = bodyHasDepthComparison(fn.node, fn.paramNames, sf);
    fn.hasCycleBreaker = bodyHasCycleBreaker(fn.node, sf);
  }

  const nameToIndex = buildNameIndex(functions);
  const edges = collectEdges(functions, nameToIndex, sf);
  const cycles = detectCycles(functions, edges, sf, file);
  return { file, cycles, isTestFile: false };
}

// ─── Test-file structural detection ────────────────────────────────────────

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

// ─── Function collection ──────────────────────────────────────────────────

function collectFunctions(sf: ts.SourceFile, file: string): FunctionNode[] {
  const functions: FunctionNode[] = [];
  visit(sf);
  return functions;

  function visit(node: ts.Node): void {
    if (ts.isFunctionDeclaration(node) && node.name && node.body) {
      pushFunction(node.name.text, node, node.parameters);
    } else if (ts.isMethodDeclaration(node) && node.body) {
      const name = propertyNameText(node.name);
      if (name) pushFunction(name, node, node.parameters);
    } else if (
      ts.isVariableDeclaration(node) &&
      node.initializer &&
      (ts.isFunctionExpression(node.initializer) || ts.isArrowFunction(node.initializer)) &&
      ts.isIdentifier(node.name)
    ) {
      pushFunction(node.name.text, node.initializer, node.initializer.parameters);
    }
    ts.forEachChild(node, visit);
  }

  function pushFunction(
    name: string,
    body: ts.Node,
    params: ts.NodeArray<ts.ParameterDeclaration>,
  ): void {
    const headerLocation = sourceLocation(sf, file, body);
    const paramNames: string[] = [];
    for (const p of params) {
      if (ts.isIdentifier(p.name)) paramNames.push(p.name.text.toLowerCase());
    }
    functions.push({
      name,
      node: body,
      headerLocation,
      paramNames,
      hasDepthComparison: false,
      hasCycleBreaker: false,
      observedEntry: lineTextAt(sf, body.getStart(sf)).trim().slice(0, 200),
    });
  }
}

function buildNameIndex(functions: FunctionNode[]): Map<string, number> {
  const out = new Map<string, number>();
  functions.forEach((fn, i) => {
    if (!out.has(fn.name)) out.set(fn.name, i);
  });
  return out;
}

// ─── Guard analysis ───────────────────────────────────────────────────────

/**
 * True iff the function body contains a BinaryExpression comparing an
 * identifier whose name matches a known depth parameter to either a
 * NumericLiteral or an identifier starting with an UPPER_SNAKE prefix
 * from DEPTH_CONSTANT_PREFIXES.
 *
 * A NumericLiteral comparison (`if (depth > 10)`) is also accepted.
 */
function bodyHasDepthComparison(
  fn: ts.Node,
  paramNames: readonly string[],
  _sf: ts.SourceFile,
): boolean {
  const paramSet = new Set(paramNames.filter((n) => DEPTH_PARAM_SET.has(n)));
  if (paramSet.size === 0) {
    // Fallback: any local identifier that MATCHES a depth-parameter name is
    // accepted as a proxy guard (e.g. `let depth = 0;` inside the function).
    // We still require the comparison check below.
  }

  let found = false;

  function visit(node: ts.Node): void {
    if (found) return;
    if (ts.isBinaryExpression(node)) {
      const op = node.operatorToken.kind;
      if (isComparisonOperator(op)) {
        if (sideReferencesDepthParam(node.left, paramSet) && sideIsUpperBoundOrNumeric(node.right)) {
          found = true;
          return;
        }
        if (sideReferencesDepthParam(node.right, paramSet) && sideIsUpperBoundOrNumeric(node.left)) {
          found = true;
          return;
        }
      }
    }
    ts.forEachChild(node, visit);
  }

  ts.forEachChild(fn, visit);
  return found;
}

function isComparisonOperator(op: ts.SyntaxKind): boolean {
  return (
    op === ts.SyntaxKind.GreaterThanToken ||
    op === ts.SyntaxKind.GreaterThanEqualsToken ||
    op === ts.SyntaxKind.LessThanToken ||
    op === ts.SyntaxKind.LessThanEqualsToken ||
    op === ts.SyntaxKind.EqualsEqualsToken ||
    op === ts.SyntaxKind.EqualsEqualsEqualsToken
  );
}

function sideReferencesDepthParam(
  expr: ts.Expression,
  paramSet: ReadonlySet<string>,
): boolean {
  if (ts.isIdentifier(expr)) {
    const name = expr.text.toLowerCase();
    if (paramSet.has(name)) return true;
    if (DEPTH_PARAM_SET.has(name)) return true;
  }
  return false;
}

function sideIsUpperBoundOrNumeric(expr: ts.Expression): boolean {
  if (ts.isNumericLiteral(expr)) return true;
  if (ts.isPrefixUnaryExpression(expr) && ts.isNumericLiteral(expr.operand)) return true;
  if (ts.isIdentifier(expr)) {
    for (const prefix of DEPTH_CONSTANT_PREFIX_LIST) {
      if (expr.text.startsWith(prefix)) return true;
    }
    // Standalone UPPER_SNAKE identifier is a common guard idiom.
    if (isUpperSnake(expr.text)) return true;
  }
  if (ts.isPropertyAccessExpression(expr)) {
    // e.g. CONFIG.MAX_DEPTH / this.MAX_DEPTH
    const tail = expr.name.text;
    for (const prefix of DEPTH_CONSTANT_PREFIX_LIST) {
      if (tail.startsWith(prefix)) return true;
    }
    if (isUpperSnake(tail)) return true;
  }
  return false;
}

function isUpperSnake(s: string): boolean {
  if (s.length < 3) return false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    const isUpper = ch >= "A" && ch <= "Z";
    const isDigit = ch >= "0" && ch <= "9";
    const isUnderscore = ch === "_";
    if (!isUpper && !isDigit && !isUnderscore) return false;
  }
  // Require at least one underscore OR be fully uppercase word of length ≥ 4.
  return s.includes("_") || s.length >= 4;
}

/**
 * True iff the function body contains a visited-set:
 *   - a NewExpression whose constructor is Set / Map / WeakSet / WeakMap, AND
 *   - a subsequent CallExpression on a PropertyAccessExpression whose method
 *     is `.has` / `.add` / `.get` / `.set`.
 *
 * We accept the constructor + method-call pair as a cycle-breaker signal.
 * Proving the method is called on the specific visited-set instance is a
 * cross-scope analysis we don't do — the signal is a CONFIDENCE factor,
 * not a binding mitigation.
 */
function bodyHasCycleBreaker(fn: ts.Node, _sf: ts.SourceFile): boolean {
  let ctorSeen = false;
  let methodCallSeen = false;

  function visit(node: ts.Node): void {
    if (ctorSeen && methodCallSeen) return;
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression)) {
      if (CYCLE_BREAKER_TYPE_SET.has(node.expression.text.toLowerCase())) {
        ctorSeen = true;
      }
    }
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const method = node.expression.name.text.toLowerCase();
      if (CYCLE_BREAKER_METHOD_SET.has(method)) {
        methodCallSeen = true;
      }
    }
    ts.forEachChild(node, visit);
  }

  ts.forEachChild(fn, visit);
  return ctorSeen && methodCallSeen;
}

// ─── Edge collection ──────────────────────────────────────────────────────

function collectEdges(
  functions: FunctionNode[],
  nameToIndex: ReadonlyMap<string, number>,
  sf: ts.SourceFile,
): RecursionEdge[] {
  const edges: RecursionEdge[] = [];

  functions.forEach((fn, fromIndex) => {
    ts.forEachChild(fn.node, function walk(node) {
      if (ts.isCallExpression(node)) {
        pushEdgesFromCall(node, fromIndex);
      }
      ts.forEachChild(node, walk);
    });
  });

  function pushEdgesFromCall(call: ts.CallExpression, fromIndex: number): void {
    // Direct call: identifier callee matching a known function name.
    if (ts.isIdentifier(call.expression)) {
      const toIndex = nameToIndex.get(call.expression.text);
      if (toIndex !== undefined) {
        edges.push({
          fromIndex,
          toIndex,
          kind: fromIndex === toIndex ? "direct-self-call" : "mutual-recursion",
          callNode: call,
        });
      }
      return;
    }

    // Method call: receiver.method(...) — three synthesis branches.
    if (ts.isPropertyAccessExpression(call.expression)) {
      const recvNode = call.expression.expression;
      const method = call.expression.name.text;
      const methodLower = method.toLowerCase();

      // (a) Self-reference via this.method() / self.method(). Covers both
      //     the ThisKeyword path and the named `self` / `this` identifier
      //     binding that agentic patterns often use.
      const isSelfReceiver =
        recvNode.kind === ts.SyntaxKind.ThisKeyword ||
        (ts.isIdentifier(recvNode) &&
          (recvNode.text === "self" || recvNode.text === "this"));
      if (isSelfReceiver) {
        const toIndex = nameToIndex.get(method);
        if (toIndex !== undefined) {
          edges.push({
            fromIndex,
            toIndex,
            kind: fromIndex === toIndex ? "direct-self-call" : "mutual-recursion",
            callNode: call,
          });
        }
      }

      // (b) Tool-call synthesis: recognised receiver + recognised method +
      // string-literal first argument naming another function.
      if (
        ts.isIdentifier(recvNode) &&
        TOOL_CALL_RECEIVER_SET.has(recvNode.text.toLowerCase()) &&
        TOOL_CALL_METHOD_SET.has(methodLower)
      ) {
        const firstArg = call.arguments[0];
        if (firstArg && (ts.isStringLiteral(firstArg) || ts.isNoSubstitutionTemplateLiteral(firstArg))) {
          const targetName = firstArg.text;
          const toIndex = nameToIndex.get(targetName);
          if (toIndex !== undefined) {
            edges.push({
              fromIndex,
              toIndex,
              kind: "tool-call-roundtrip",
              callNode: call,
            });
          }
        }
      }

      // (c) Emit-style: emitter.emit("name") / dispatcher.dispatch("name").
      if (methodLower === "emit" || methodLower === "dispatch") {
        const firstArg = call.arguments[0];
        if (firstArg && (ts.isStringLiteral(firstArg) || ts.isNoSubstitutionTemplateLiteral(firstArg))) {
          const targetName = firstArg.text;
          const toIndex = nameToIndex.get(targetName);
          if (toIndex !== undefined) {
            edges.push({
              fromIndex,
              toIndex,
              kind: "emit-roundtrip",
              callNode: call,
            });
          }
        }
      }
    }
  }

  // Silence unused parameter.
  void sf;

  return edges;
}

// ─── Tarjan SCC ───────────────────────────────────────────────────────────

interface SCC {
  /** Indices of functions in the SCC. */
  nodes: number[];
  /** Edges participating in this SCC (both endpoints in `nodes`). */
  edges: RecursionEdge[];
}

function detectCycles(
  functions: FunctionNode[],
  edges: RecursionEdge[],
  sf: ts.SourceFile,
  file: string,
): RecursionCycle[] {
  const sccs = tarjanSCC(functions.length, edges);
  const cycles: RecursionCycle[] = [];

  for (const scc of sccs) {
    const isRecursive = isRecursiveSCC(scc);
    if (!isRecursive) continue;

    // Pick the canonical entry function: the lowest-indexed function in
    // the SCC — stable and deterministic.
    const entryIndex = Math.min(...scc.nodes);
    const entry = functions[entryIndex];

    // Pick a representative closing edge: prefer the most specific edge
    // kind (tool-call / emit beat mutual / direct for visibility), then
    // the earliest position in the file.
    const edgeKindPriority: Record<RecursionEdgeKind, number> = {
      "tool-call-roundtrip": 0,
      "emit-roundtrip": 1,
      "mutual-recursion": 2,
      "direct-self-call": 3,
    };
    const closingEdge = [...scc.edges].sort((a, b) => {
      const pa = edgeKindPriority[a.kind];
      const pb = edgeKindPriority[b.kind];
      if (pa !== pb) return pa - pb;
      return a.callNode.getStart(sf) - b.callNode.getStart(sf);
    })[0];

    if (!closingEdge) continue;

    const hasDepthParameter = entry.paramNames.some((p) => DEPTH_PARAM_SET.has(p));
    const hasDepthComparison = entry.hasDepthComparison;
    const hasCycleBreaker = entry.hasCycleBreaker;

    // A finding is emitted only when the cycle lacks BOTH the comparison
    // and the cycle-breaker. A depth parameter without a comparison is
    // NOT a guard — the charter's lethal edge case 2.
    if (hasDepthComparison || hasCycleBreaker) continue;

    cycles.push({
      callLocation: sourceLocation(sf, file, closingEdge.callNode),
      entryLocation: entry.headerLocation,
      entryLabel: entry.name,
      cycleMembers: scc.nodes.map((i) => functions[i].name),
      edgeKind: closingEdge.kind,
      observedCall: lineTextAt(sf, closingEdge.callNode.getStart(sf)).trim().slice(0, 200),
      observedEntry: entry.observedEntry,
      hasDepthParameter,
      hasDepthComparison,
      hasCycleBreaker,
    });
  }

  return cycles;
}

function isRecursiveSCC(scc: SCC): boolean {
  if (scc.nodes.length >= 2) return true;
  // Single-node SCC — recursive only if there is a self-edge.
  const only = scc.nodes[0];
  return scc.edges.some((e) => e.fromIndex === only && e.toIndex === only);
}

function tarjanSCC(n: number, edges: readonly RecursionEdge[]): SCC[] {
  const adj: number[][] = Array.from({ length: n }, () => []);
  for (const e of edges) adj[e.fromIndex].push(e.toIndex);

  let index = 0;
  const indexOf = new Array<number>(n).fill(-1);
  const lowlink = new Array<number>(n).fill(-1);
  const onStack = new Array<boolean>(n).fill(false);
  const stack: number[] = [];
  const sccs: SCC[] = [];

  for (let i = 0; i < n; i++) {
    if (indexOf[i] === -1) strongConnect(i);
  }

  function strongConnect(v: number): void {
    indexOf[v] = index;
    lowlink[v] = index;
    index++;
    stack.push(v);
    onStack[v] = true;

    for (const w of adj[v]) {
      if (indexOf[w] === -1) {
        strongConnect(w);
        lowlink[v] = Math.min(lowlink[v], lowlink[w]);
      } else if (onStack[w]) {
        lowlink[v] = Math.min(lowlink[v], indexOf[w]);
      }
    }

    if (lowlink[v] === indexOf[v]) {
      const sccNodes: number[] = [];
      let w: number;
      do {
        w = stack.pop()!;
        onStack[w] = false;
        sccNodes.push(w);
      } while (w !== v);

      const sccSet = new Set(sccNodes);
      const sccEdges = edges.filter(
        (e) => sccSet.has(e.fromIndex) && sccSet.has(e.toIndex),
      );
      sccs.push({ nodes: sccNodes.sort((a, b) => a - b), edges: sccEdges });
    }
  }

  return sccs;
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
