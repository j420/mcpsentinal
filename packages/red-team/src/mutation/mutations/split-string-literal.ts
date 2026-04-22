/**
 * Mutation: split-string-literal
 *
 * Splits the FIRST string literal with length > 4 at an arbitrary boundary
 * using `+`. E.g. `"ignore previous instructions"` →
 * `"ignore " + "previous instructions"`.
 *
 * Tests whether rules that look at raw string literal text (linguistic /
 * regex-like signals) can reassemble split literals. A rule that only walks
 * the AST looking for StringLiteral nodes will see two shorter literals and
 * miss the original phrase.
 *
 * Applies to: any fixture containing a single-quoted, double-quoted, or
 * no-substitution template literal with > 4 characters. Skips template
 * literals with substitutions (structural interpolation is already split).
 */

import ts from "typescript";
import type { MutationFn, MutationResult } from "../types.js";

const FIXTURE_FILENAME = "fixture.ts";
const MIN_SPLIT_LEN = 5;

/**
 * Pick a split point roughly in the middle of the literal. Deterministic — no
 * randomness — so the mutation is reproducible across CI runs. A literal of
 * length N splits at floor(N / 2). A literal shorter than MIN_SPLIT_LEN is
 * skipped by the caller.
 */
function splitPoint(length: number): number {
  return Math.max(1, Math.floor(length / 2));
}

/**
 * Escape a string for embedding in a double-quoted JS/TS literal. Covers the
 * backslash, double quote, newline, carriage return, and tab cases that show
 * up in the analyzer's fixtures. Intentionally does NOT escape single quotes
 * (they're legal inside a double-quoted string).
 */
function escapeForDoubleQuote(raw: string): string {
  let out = "";
  for (const ch of raw) {
    if (ch === "\\") out += "\\\\";
    else if (ch === '"') out += '\\"';
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else out += ch;
  }
  return out;
}

export const splitStringLiteral: MutationFn = (source: string): MutationResult => {
  const sf = ts.createSourceFile(FIXTURE_FILENAME, source, ts.ScriptTarget.Latest, /*setParentNodes*/ true, ts.ScriptKind.TS);

  // Locate the first splittable literal in source order. We use a depth-first
  // visit that bails as soon as it finds one — keeps the transformation local
  // and reviewable. The runner is free to call this mutation again on the
  // result if it wants "split N literals", but for a first-pass audit one
  // split is sufficient signal.
  let targetStart = -1;
  let targetEnd = -1;
  let targetText = "";

  const visit = (node: ts.Node): boolean => {
    if (targetStart !== -1) return true;
    if (ts.isStringLiteral(node) || (ts.isNoSubstitutionTemplateLiteral(node))) {
      const literalText = node.text;
      if (literalText.length >= MIN_SPLIT_LEN) {
        targetStart = node.getStart(sf);
        targetEnd = node.getEnd();
        targetText = literalText;
        return true;
      }
    }
    return ts.forEachChild(node, visit) ?? false;
  };
  visit(sf);

  if (targetStart === -1) {
    return { mutated: source, notes: "not-applicable" };
  }

  const mid = splitPoint(targetText.length);
  const left = targetText.slice(0, mid);
  const right = targetText.slice(mid);
  const replacement = `"${escapeForDoubleQuote(left)}" + "${escapeForDoubleQuote(right)}"`;

  const mutated = source.slice(0, targetStart) + replacement + source.slice(targetEnd);
  return { mutated };
};
