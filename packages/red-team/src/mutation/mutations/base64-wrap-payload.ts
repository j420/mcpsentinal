/**
 * Mutation: base64-wrap-payload
 *
 * Wrap the FIRST string literal with ≥ 5 characters in a
 * `Buffer.from("<base64>", "base64").toString()` call. The runtime value is
 * unchanged; what the rule sees (if it reads source text / AST literals) is
 * now a base64 blob plus a decode call.
 *
 * Tests whether rules that look at raw literal text miss the encoded form.
 * A9 is designed to handle this. Most other description / linguistic rules
 * will NOT — that's the honest outcome; the CHARTER for those rules should
 * list this mutation under `mutations_acknowledged_blind`.
 *
 * Why ≥ 5 chars: tiny strings produce a base64 blob that is itself shorter
 * than some linguistic thresholds, which is a noise source rather than a
 * meaningful blind-spot probe.
 */

import ts from "typescript";
import type { MutationFn, MutationResult } from "../types.js";

const FIXTURE_FILENAME = "fixture.ts";
const MIN_LENGTH = 5;

export const base64WrapPayload: MutationFn = (source: string): MutationResult => {
  const sf = ts.createSourceFile(FIXTURE_FILENAME, source, ts.ScriptTarget.Latest, /*setParentNodes*/ true, ts.ScriptKind.TS);

  let targetStart = -1;
  let targetEnd = -1;
  let targetText = "";

  const visit = (node: ts.Node): boolean => {
    if (targetStart !== -1) return true;
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      if (node.text.length >= MIN_LENGTH) {
        targetStart = node.getStart(sf);
        targetEnd = node.getEnd();
        targetText = node.text;
        return true;
      }
    }
    return ts.forEachChild(node, visit) ?? false;
  };
  visit(sf);

  if (targetStart === -1) {
    return { mutated: source, notes: "not-applicable" };
  }

  // Encode in base64 (Node Buffer is the analyzer runtime's canonical path).
  const b64 = Buffer.from(targetText, "utf8").toString("base64");
  const replacement = `Buffer.from("${b64}", "base64").toString()`;

  const mutated = source.slice(0, targetStart) + replacement + source.slice(targetEnd);
  return { mutated };
};
