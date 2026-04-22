/**
 * Mutation: intermediate-variable
 *
 * Insert a pass-through `const` between a taint source and its sink. Given
 * `exec(process.argv[2])`, produce:
 *
 *     const _mut_v0 = process.argv[2];
 *     const _mut_v1 = _mut_v0;
 *     exec(_mut_v1);
 *
 * Tests whether taint rules handle N-hop propagation through trivial
 * pass-through bindings. A rule that only chains one source → sink hop will
 * miss this; a real def-use analysis will follow the chain.
 *
 * To keep the mutation surface small, we only target call expressions whose
 * callee is one of a closed set of sinks AND whose first argument is a
 * PropertyAccessExpression, ElementAccessExpression, or CallExpression (the
 * canonical "taint source" shapes). If no such call site is present, the
 * mutation is not-applicable.
 */

import ts from "typescript";
import type { MutationFn, MutationResult } from "../types.js";

const FIXTURE_FILENAME = "fixture.ts";

// Closed sink list — same principle as rename-danger-symbol: no regex, no
// long heuristic array, just the high-signal sinks whose taint chains we
// care about.
const DANGER_SINKS: ReadonlyArray<string> = [
  "exec",
  "spawn",
  "eval",
  "system",
];

interface CallSiteWithTaintArg {
  /** The entire call expression. */
  call: ts.CallExpression;
  /** Offset of the first argument. */
  argStart: number;
  argEnd: number;
  /** The enclosing statement — we prepend the intermediate bindings here. */
  enclosingStatement: ts.Statement;
  /** The source text of the first argument. */
  argText: string;
  /** Column indent of the enclosing statement. */
  indent: string;
}

function findEnclosingStatement(node: ts.Node): ts.Statement | null {
  let cur: ts.Node | undefined = node;
  while (cur) {
    if (ts.isStatement(cur)) return cur;
    cur = cur.parent;
  }
  return null;
}

function isTaintSourceShape(expr: ts.Expression): boolean {
  return (
    ts.isPropertyAccessExpression(expr) ||
    ts.isElementAccessExpression(expr) ||
    ts.isCallExpression(expr) ||
    ts.isIdentifier(expr)
  );
}

export const intermediateVariable: MutationFn = (source: string): MutationResult => {
  const sf = ts.createSourceFile(FIXTURE_FILENAME, source, ts.ScriptTarget.Latest, /*setParentNodes*/ true, ts.ScriptKind.TS);

  let target: CallSiteWithTaintArg | null = null;

  const visit = (node: ts.Node): void => {
    if (target) return;
    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const calleeName = ts.isIdentifier(callee)
        ? callee.text
        : ts.isPropertyAccessExpression(callee)
          ? callee.name.text
          : null;

      if (calleeName && DANGER_SINKS.includes(calleeName)) {
        const firstArg = node.arguments[0];
        if (firstArg && isTaintSourceShape(firstArg)) {
          const stmt = findEnclosingStatement(node);
          if (stmt) {
            const stmtStart = stmt.getStart(sf);
            const lineStart = source.lastIndexOf("\n", stmtStart - 1) + 1;
            const indent = source.slice(lineStart, stmtStart).match(/^[ \t]*/)?.[0] ?? "";
            target = {
              call: node,
              argStart: firstArg.getStart(sf),
              argEnd: firstArg.getEnd(),
              enclosingStatement: stmt,
              argText: source.slice(firstArg.getStart(sf), firstArg.getEnd()),
              indent,
            };
            return;
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  if (!target) {
    return { mutated: source, notes: "not-applicable" };
  }

  const hit: CallSiteWithTaintArg = target;
  const v0 = "_mut_v0";
  const v1 = "_mut_v1";
  const bindings = `${hit.indent}const ${v0} = ${hit.argText};\n${hit.indent}const ${v1} = ${v0};\n`;

  // Insert the bindings before the enclosing statement, then replace the first
  // argument with v1. We build the mutation in two steps to keep offsets
  // simple: insert first, then replace in the inserted-copy with shift-adjusted
  // offsets.
  const stmtStart = hit.enclosingStatement.getStart(sf);
  const withBindings = source.slice(0, stmtStart) + bindings + source.slice(stmtStart);

  const shift = bindings.length;
  const newArgStart = hit.argStart + shift;
  const newArgEnd = hit.argEnd + shift;

  const mutated =
    withBindings.slice(0, newArgStart) +
    v1 +
    withBindings.slice(newArgEnd);

  return { mutated };
};
