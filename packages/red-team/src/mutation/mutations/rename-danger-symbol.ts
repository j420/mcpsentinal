/**
 * Mutation: rename-danger-symbol
 *
 * Renames the FIRST sensitive-sink identifier at its call site via an alias.
 * E.g. `exec(x)` → `const _mut_exec = exec; _mut_exec(x)`.
 *
 * This tests whether the rule resolves symbol bindings vs. name-matches the
 * literal identifier token. A taint analysis built on the TS compiler's
 * symbol table should follow the alias; a name-based scan that looks for the
 * token "exec" will miss it.
 *
 * The list of sensitive sinks is a short, explicit array (≤5 entries per the
 * project's no-static-patterns convention — this list IS the code under
 * test). We pick from a closed set of high-severity sinks that appear across
 * many rules' fixtures; if none are present, the mutation is not-applicable.
 */

import ts from "typescript";
import type { MutationFn, MutationResult } from "../types.js";

const FIXTURE_FILENAME = "fixture.ts";

// Closed, auditable list. Not a heuristic — these are the tokens whose
// binding resolution we want every taint rule to be able to follow.
const DANGER_SINKS: ReadonlyArray<string> = [
  "exec",
  "spawn",
  "eval",
  "system",
];

interface CallSite {
  /** The identifier node at the call site (node.expression of a CallExpression). */
  identifier: ts.Identifier;
  /** Full source offset of the call expression. */
  callStart: number;
  /** Name of the sink. */
  name: string;
  /** The enclosing statement (so we can prepend the alias binding). */
  enclosingStatement: ts.Statement | null;
}

function findEnclosingStatement(node: ts.Node): ts.Statement | null {
  let cur: ts.Node | undefined = node;
  while (cur) {
    if (ts.isStatement(cur)) return cur;
    cur = cur.parent;
  }
  return null;
}

export const renameDangerSymbol: MutationFn = (source: string): MutationResult => {
  const sf = ts.createSourceFile(FIXTURE_FILENAME, source, ts.ScriptTarget.Latest, /*setParentNodes*/ true, ts.ScriptKind.TS);

  let target: CallSite | null = null;

  const visit = (node: ts.Node): void => {
    if (target) return;
    if (ts.isCallExpression(node)) {
      // Only rewrite plain identifier calls: `exec(...)`. Skip
      // PropertyAccessExpression calls like `child_process.exec(...)` —
      // renaming the property target would require mutating both the
      // member access and the receiver, and the net behavioural change is
      // not what we want to test for an "alias-the-danger-symbol" mutation.
      const callee = node.expression;
      if (ts.isIdentifier(callee) && DANGER_SINKS.includes(callee.text)) {
        target = {
          identifier: callee,
          callStart: node.getStart(sf),
          name: callee.text,
          enclosingStatement: findEnclosingStatement(node),
        };
        return;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  if (!target) {
    return { mutated: source, notes: "not-applicable" };
  }

  // The narrowing via forEachChild above loses TS's knowledge that target is
  // no longer null, so widen to a local non-null alias for the rest of this
  // function.
  const hit: CallSite = target;

  // Build: `const _mut_<sink> = <sink>;\n` inserted immediately before the
  // enclosing statement, and replace the identifier at the call site.
  const aliasName = `_mut_${hit.name}`;
  const stmtStart = hit.enclosingStatement
    ? hit.enclosingStatement.getStart(sf)
    : hit.callStart;

  // Preserve the column of the enclosing statement so indentation of the
  // inserted binding line roughly matches the surrounding source.
  const lineStart = source.lastIndexOf("\n", stmtStart - 1) + 1;
  const indent = source.slice(lineStart, stmtStart).match(/^[ \t]*/)?.[0] ?? "";

  const bindingLine = `${indent}const ${aliasName} = ${hit.name};\n`;

  // Replace identifier at hit.identifier range.
  const idStart = hit.identifier.getStart(sf);
  const idEnd = hit.identifier.getEnd();
  const afterIdReplacement = source.slice(0, idStart) + aliasName + source.slice(idEnd);

  // The binding-line insertion point is before the enclosing statement, but
  // that point is inside `afterIdReplacement` too. The identifier replacement
  // is *after* stmtStart (same length is arbitrary — `exec` vs `_mut_exec`),
  // so to keep offsets stable, insert the binding first in the original, then
  // apply the identifier replacement in the inserted-copy.
  const withBinding = source.slice(0, stmtStart) + bindingLine + source.slice(stmtStart);

  // Recompute the identifier offsets in the binding-inserted source. The
  // insertion shifts everything after stmtStart by bindingLine.length.
  const shift = bindingLine.length;
  const newIdStart = idStart + shift;
  const newIdEnd = idEnd + shift;
  const mutated =
    withBinding.slice(0, newIdStart) +
    aliasName +
    withBinding.slice(newIdEnd);

  // Suppress unused-variable warnings when the identifier replacement is a
  // no-op (shouldn't happen with the closed sink set, but be defensive).
  void afterIdReplacement;

  return { mutated };
};
