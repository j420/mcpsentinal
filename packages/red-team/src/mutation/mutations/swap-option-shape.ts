/**
 * Mutation: swap-option-shape
 *
 * Swap a truthy option-property assignment for a semantically-equivalent but
 * structurally different form. The canonical case:
 *
 *     exec(cmd, { shell: true })          // before
 *     exec(cmd, { shell: "bash" })        // after (same truthy value, different shape)
 *
 * This tests whether a rule that specifically matches `shell: true` misses
 * other truthy values (`shell: 1`, `shell: "bash"`) that a real attacker
 * would use. Only applies when the fixture actually uses an option object
 * with a boolean `true` property; skip otherwise → not-applicable.
 *
 * We target `shell: true` specifically — this is the high-signal option
 * shape that appears in most C1 / K-rules / P-rules fixtures. Extending the
 * set of option-shapes we rotate through would inflate the CHARTER list
 * without adding signal; keeping it to one named shape is deliberate.
 */

import ts from "typescript";
import type { MutationFn, MutationResult } from "../types.js";

const FIXTURE_FILENAME = "fixture.ts";

const TARGET_PROPERTY = "shell";

interface Hit {
  node: ts.PropertyAssignment;
  valueStart: number;
  valueEnd: number;
}

export const swapOptionShape: MutationFn = (source: string): MutationResult => {
  const sf = ts.createSourceFile(FIXTURE_FILENAME, source, ts.ScriptTarget.Latest, /*setParentNodes*/ true, ts.ScriptKind.TS);

  let target: Hit | null = null;

  const visit = (node: ts.Node): void => {
    if (target) return;
    if (ts.isPropertyAssignment(node)) {
      const nameNode = node.name;
      let name: string | null = null;
      if (ts.isIdentifier(nameNode)) name = nameNode.text;
      else if (ts.isStringLiteral(nameNode)) name = nameNode.text;

      if (name === TARGET_PROPERTY) {
        const init = node.initializer;
        if (init.kind === ts.SyntaxKind.TrueKeyword) {
          target = {
            node,
            valueStart: init.getStart(sf),
            valueEnd: init.getEnd(),
          };
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

  const hit: Hit = target;
  // Replace `true` with `"bash"` — a truthy string value. Still executes a
  // shell, still dangerous, but any rule that specifically pattern-matches
  // `shell: true` as a BooleanLiteral will see a StringLiteral and miss.
  const replacement = `"bash"`;
  const mutated = source.slice(0, hit.valueStart) + replacement + source.slice(hit.valueEnd);
  return { mutated };
};
