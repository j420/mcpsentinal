/**
 * Mutation: reorder-object-properties
 *
 * Reverse the property order of the FIRST object literal that has ≥ 2
 * properties. Runtime semantics are preserved for ordinary property access
 * (insertion order affects iteration, not lookup); any rule that reasons
 * about the POSITION of a property in an object literal (instead of its
 * name) will miss it.
 *
 * We preserve spread elements, method shorthand, and property-assignment
 * order internally by only reversing the array of ObjectLiteralElement
 * entries and rebuilding the literal from the printed text of each entry.
 * To avoid re-printing quirks, we splice the source text of each entry
 * directly — safer than round-tripping through the TS emitter.
 */

import ts from "typescript";
import type { MutationFn, MutationResult } from "../types.js";

const FIXTURE_FILENAME = "fixture.ts";

interface Hit {
  obj: ts.ObjectLiteralExpression;
  entryRanges: Array<{ start: number; end: number }>;
}

export const reorderObjectProperties: MutationFn = (source: string): MutationResult => {
  const sf = ts.createSourceFile(FIXTURE_FILENAME, source, ts.ScriptTarget.Latest, /*setParentNodes*/ true, ts.ScriptKind.TS);

  let target: Hit | null = null;

  const visit = (node: ts.Node): void => {
    if (target) return;
    if (ts.isObjectLiteralExpression(node) && node.properties.length >= 2) {
      const ranges: Array<{ start: number; end: number }> = [];
      for (const prop of node.properties) {
        ranges.push({ start: prop.getStart(sf), end: prop.getEnd() });
      }
      target = { obj: node, entryRanges: ranges };
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  if (!target) {
    return { mutated: source, notes: "not-applicable" };
  }

  const hit: Hit = target;
  const entries = hit.entryRanges.map((r) => source.slice(r.start, r.end));
  const reversed = entries.slice().reverse();

  // Rebuild the object body: take the source range that spans the first
  // entry's start to the last entry's end, and replace it with the reversed
  // entries joined by the separators from the original. To keep the output
  // readable we join with `,\n` + the indent of the first entry.
  const first = hit.entryRanges[0];
  const last = hit.entryRanges[hit.entryRanges.length - 1];

  // Detect indent of the first entry from the line prefix.
  const lineStart = source.lastIndexOf("\n", first.start - 1) + 1;
  const indent = source.slice(lineStart, first.start).match(/^[ \t]*/)?.[0] ?? "";
  const joiner = `,\n${indent}`;

  const replacement = reversed.join(joiner);
  const mutated = source.slice(0, first.start) + replacement + source.slice(last.end);
  return { mutated };
};
