/**
 * Mutation: add-noop-conditional
 *
 * Wrap the FIRST dangerous-sink call site in `if (true) { ... }`. Same
 * runtime behaviour; any rule that walks only the top-level statements of a
 * function or file will now miss the call.
 *
 * We target the statement that contains the call, not the call itself — the
 * wrap has to happen at statement level because `if (true)` expects a block.
 * This keeps the mutation syntactically sound (no expression-to-statement
 * coercion) and semantically equivalent.
 */

import ts from "typescript";
import type { MutationFn, MutationResult } from "../types.js";

const FIXTURE_FILENAME = "fixture.ts";

const DANGER_SINKS: ReadonlyArray<string> = [
  "exec",
  "spawn",
  "eval",
  "system",
];

interface StmtToWrap {
  stmt: ts.Statement;
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

export const addNoopConditional: MutationFn = (source: string): MutationResult => {
  const sf = ts.createSourceFile(FIXTURE_FILENAME, source, ts.ScriptTarget.Latest, /*setParentNodes*/ true, ts.ScriptKind.TS);

  let target: StmtToWrap | null = null;

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
        const stmt = findEnclosingStatement(node);
        if (stmt && !ts.isBlock(stmt)) {
          // Skip wrapping the enclosing block itself — that would be a
          // meaningless outer-if wrap that changes nothing.
          const stmtStart = stmt.getStart(sf);
          const lineStart = source.lastIndexOf("\n", stmtStart - 1) + 1;
          const indent = source.slice(lineStart, stmtStart).match(/^[ \t]*/)?.[0] ?? "";
          target = { stmt, indent };
          return;
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  if (!target) {
    return { mutated: source, notes: "not-applicable" };
  }

  const hit: StmtToWrap = target;
  const start = hit.stmt.getStart(sf);
  const end = hit.stmt.getEnd();
  const stmtText = source.slice(start, end);

  const wrapped = `if (true) {\n${hit.indent}  ${stmtText}\n${hit.indent}}`;
  const mutated = source.slice(0, start) + wrapped + source.slice(end);
  return { mutated };
};
