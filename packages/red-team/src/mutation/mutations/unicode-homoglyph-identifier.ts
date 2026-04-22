/**
 * Mutation: unicode-homoglyph-identifier
 *
 * Inside a single string LITERAL (not an identifier used at runtime), replace
 * one Latin character with its visually-identical Cyrillic or Greek
 * homoglyph. E.g. `"system_prompt"` → `"system_prоmpt"` (Cyrillic о U+043E).
 *
 * Why only inside literals? Replacing a runtime identifier (like a variable
 * or property name) would change what the code actually does — a homoglyph
 * `identifier` is a DIFFERENT identifier at runtime. That would break the
 * fixture in a way that's not about the rule's blind-spot, it's about
 * introducing a runtime behavioural change. Replacing characters inside a
 * string literal leaves runtime behaviour intact; only the text SEEN by the
 * rule changes.
 *
 * Tests whether A6/A7/G-rules detect Unicode evasion beyond their canonical
 * signal, and also whether linguistic rules (A1, J5, J6) are brittle when the
 * attacker uses a homoglyph to bypass a pure Latin pattern.
 */

import ts from "typescript";
import type { MutationFn, MutationResult } from "../types.js";

const FIXTURE_FILENAME = "fixture.ts";

// Closed, auditable homoglyph map. The spec requires ≤5 string-array
// constants; this sits at 4 Latin→Cyrillic pairs covering the most common
// substitutions in real attacks.
const HOMOGLYPHS: ReadonlyArray<[string, string]> = [
  ["a", "а"], // Cyrillic а
  ["o", "о"], // Cyrillic о
  ["e", "е"], // Cyrillic е
  ["p", "р"], // Cyrillic р
];

function pickSubstitution(literalText: string): { index: number; replacement: string } | null {
  // Deterministic: scan left-to-right for the first character that has a
  // homoglyph mapping AND whose substitution would leave the string non-empty.
  for (let i = 0; i < literalText.length; i++) {
    const ch = literalText[i];
    for (const [latin, cyr] of HOMOGLYPHS) {
      if (ch === latin) {
        return { index: i, replacement: cyr };
      }
    }
  }
  return null;
}

/** Escape for a double-quoted JS/TS literal. Only the minimum set the
 * analyzer's fixtures actually use. */
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

export const unicodeHomoglyphIdentifier: MutationFn = (source: string): MutationResult => {
  const sf = ts.createSourceFile(FIXTURE_FILENAME, source, ts.ScriptTarget.Latest, /*setParentNodes*/ true, ts.ScriptKind.TS);

  interface Hit {
    start: number;
    end: number;
    text: string;
    index: number;
    replacement: string;
  }
  let hit: Hit | null = null;

  const visit = (node: ts.Node): boolean => {
    if (hit) return true;
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      const candidate = pickSubstitution(node.text);
      if (candidate) {
        hit = {
          start: node.getStart(sf),
          end: node.getEnd(),
          text: node.text,
          index: candidate.index,
          replacement: candidate.replacement,
        };
        return true;
      }
    }
    return ts.forEachChild(node, visit) ?? false;
  };
  visit(sf);

  if (!hit) {
    return { mutated: source, notes: "not-applicable" };
  }

  const h: Hit = hit;
  const mutatedLiteral =
    h.text.slice(0, h.index) +
    h.replacement +
    h.text.slice(h.index + 1);

  const replacement = `"${escapeForDoubleQuote(mutatedLiteral)}"`;
  const mutated = source.slice(0, h.start) + replacement + source.slice(h.end);
  return { mutated };
};
