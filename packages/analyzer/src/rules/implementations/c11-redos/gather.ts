/**
 * C11 — ReDoS: AST-driven fact gathering with structural pattern
 * analysis.
 *
 * Walks the TS compiler AST for two shapes:
 *
 *   1. RegularExpressionLiteral nodes. The literal's pattern text is
 *      passed to a hand-coded structural analyser that looks for:
 *        - nested quantifiers like (X+)+ / (X*)+ / (X+){n,}
 *        - alternation overlap like (a|a)+ / (a|ab)+
 *        - polynomial blow-up like (.*)*  / (.+)+
 *      Detection logic is character-walking — NO REGEX, by design
 *      (the no-static-patterns guard would reject it, and ironically
 *      a regex to detect dangerous regex is itself a ReDoS risk).
 *
 *   2. NewExpression / CallExpression of RegExp whose first argument
 *      is anything other than a string literal — `new RegExp(req.body.pattern)`
 *      gives the user direct control of the regex engine.
 *
 * Zero regex literals.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  LINEAR_TIME_ENGINE_NAMES,
  LENGTH_BOUND_TOKENS,
} from "./data/config.js";

export type C11LeakKind =
  | "user-controlled-pattern"
  | "nested-quantifier"
  | "alternation-overlap"
  | "polynomial-blowup";

export interface RedosFact {
  readonly kind: C11LeakKind;
  readonly location: Location;
  readonly observed: string;
  readonly mitigationPresent: boolean;
}

export interface C11GatherResult {
  readonly mode: "absent" | "test-file" | "facts";
  readonly file: string;
  readonly facts: readonly RedosFact[];
}

const SYNTHETIC_FILE = "<source>";
const TEST_FILE_RUNNER_MARKERS: readonly string[] = [
  'from "vitest"',
  "from 'vitest'",
  'from "@jest/globals"',
  "from '@jest/globals'",
  "import pytest",
];
const TEST_FILE_SUITE_MARKERS: readonly string[] = [
  "\ndescribe(",
  "\nit(",
  "\ntest(",
];

export function gatherC11(context: AnalysisContext): C11GatherResult {
  const source = context.source_code;
  if (!source || source.length === 0) {
    return { mode: "absent", file: SYNTHETIC_FILE, facts: [] };
  }
  if (looksLikeTestFile(source)) {
    return { mode: "test-file", file: SYNTHETIC_FILE, facts: [] };
  }

  const file = SYNTHETIC_FILE;
  const facts: RedosFact[] = [];
  const mitigationPresent = sourceHasMitigation(source);

  try {
    const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
    ts.forEachChild(sf, function visit(node) {
      if (ts.isRegularExpressionLiteral(node)) {
        inspectRegexLiteral(node, sf, file, facts, mitigationPresent);
      }
      if (ts.isNewExpression(node) || ts.isCallExpression(node)) {
        inspectRegexConstructor(node, sf, file, facts, mitigationPresent);
      }
      ts.forEachChild(node, visit);
    });
  } catch {
    // Parse failure: nothing to emit.
  }

  return {
    mode: facts.length > 0 ? "facts" : "absent",
    file,
    facts,
  };
}

function inspectRegexLiteral(
  node: ts.RegularExpressionLiteral,
  sf: ts.SourceFile,
  file: string,
  facts: RedosFact[],
  mitigationPresent: boolean,
): void {
  const text = node.text;
  // text is the full regex including delimiters and flags: /pattern/flags
  // Strip the leading / and trailing /flags.
  const stripped = stripRegexDelimiters(text);
  if (stripped === null) return;
  const kinds = analyseRegexPattern(stripped);
  for (const kind of kinds) {
    facts.push({
      kind,
      location: locationOf(node, sf, file),
      observed: truncate(text, 160),
      mitigationPresent,
    });
  }
}

function inspectRegexConstructor(
  node: ts.NewExpression | ts.CallExpression,
  sf: ts.SourceFile,
  file: string,
  facts: RedosFact[],
  mitigationPresent: boolean,
): void {
  const callee = node.expression;
  if (!ts.isIdentifier(callee)) return;
  if (callee.text !== "RegExp") return;
  if (!node.arguments || node.arguments.length === 0) return;
  const first = node.arguments[0];
  // String literal: analyse the pattern.
  if (ts.isStringLiteral(first) || ts.isNoSubstitutionTemplateLiteral(first)) {
    const kinds = analyseRegexPattern(first.text);
    for (const kind of kinds) {
      facts.push({
        kind,
        location: locationOf(node, sf, file),
        observed: truncate(node.getText(sf), 160),
        mitigationPresent,
      });
    }
    return;
  }
  // Anything else (Identifier, PropertyAccess, TemplateExpression, BinaryExpression):
  // the pattern is user-controllable — fire user-controlled-pattern.
  facts.push({
    kind: "user-controlled-pattern",
    location: locationOf(node, sf, file),
    observed: truncate(node.getText(sf), 160),
    mitigationPresent,
  });
}

// ─── Structural pattern analyser ─────────────────────────────────────────

/**
 * Hand-coded scanner. Returns the union of dangerous-shape kinds found
 * in the pattern text (without delimiters, without flags).
 *
 * Heuristics — conservative rather than exhaustive:
 *   - nested-quantifier: a group `(...)` whose body contains a `+` or `*`
 *     or `{n,}` quantifier AND is itself followed by a `+` / `*` / `{n,}`.
 *   - alternation-overlap: a group containing `|` AND followed by a
 *     `+` / `*` / `{n,}` quantifier.
 *   - polynomial-blowup: explicit `(.*)*` / `(.+)+` / `(.*)+` / `(.+)*`.
 *
 * The scanner skips character classes `[...]` and escape sequences.
 */
function analyseRegexPattern(pattern: string): C11LeakKind[] {
  const kinds: Set<C11LeakKind> = new Set();
  const groups = extractTopLevelGroups(pattern);
  for (const g of groups) {
    if (g.followedByQuantifier === false) continue;
    // polynomial-blowup
    if (g.body === ".*" || g.body === ".+") {
      kinds.add("polynomial-blowup");
      continue;
    }
    // alternation overlap
    if (g.containsAlternation) {
      kinds.add("alternation-overlap");
    }
    // nested quantifier: group's body contains a quantifier
    if (containsQuantifier(g.body)) {
      kinds.add("nested-quantifier");
    }
  }
  return Array.from(kinds);
}

interface GroupSpan {
  body: string;
  containsAlternation: boolean;
  followedByQuantifier: boolean;
}

function extractTopLevelGroups(pattern: string): GroupSpan[] {
  const out: GroupSpan[] = [];
  let i = 0;
  const n = pattern.length;
  while (i < n) {
    const c = pattern[i];
    if (c === "\\") {
      i += 2;
      continue;
    }
    if (c === "[") {
      // skip character class
      i++;
      while (i < n && pattern[i] !== "]") {
        if (pattern[i] === "\\") i += 2;
        else i++;
      }
      i++;
      continue;
    }
    if (c === "(") {
      // find matching close paren, respecting nested groups
      let depth = 1;
      let j = i + 1;
      // Skip over `?:` `?=` `?!` non-capturing / lookaround prefix
      if (pattern[j] === "?") j += 2;
      const bodyStart = j;
      while (j < n && depth > 0) {
        const cj = pattern[j];
        if (cj === "\\") {
          j += 2;
          continue;
        }
        if (cj === "[") {
          j++;
          while (j < n && pattern[j] !== "]") {
            if (pattern[j] === "\\") j += 2;
            else j++;
          }
          j++;
          continue;
        }
        if (cj === "(") depth++;
        else if (cj === ")") depth--;
        if (depth === 0) break;
        j++;
      }
      const body = pattern.slice(bodyStart, j);
      // Look at character after closing paren for quantifier
      const after = pattern[j + 1];
      const followedByQuantifier =
        after === "+" || after === "*" || (after === "{" && containsCommaQuantifier(pattern, j + 1));
      out.push({
        body,
        containsAlternation: containsTopLevelAlternation(body),
        followedByQuantifier,
      });
      i = j + 1;
      continue;
    }
    i++;
  }
  return out;
}

function containsQuantifier(body: string): boolean {
  let i = 0;
  const n = body.length;
  while (i < n) {
    const c = body[i];
    if (c === "\\") {
      i += 2;
      continue;
    }
    if (c === "[") {
      i++;
      while (i < n && body[i] !== "]") {
        if (body[i] === "\\") i += 2;
        else i++;
      }
      i++;
      continue;
    }
    if (c === "+" || c === "*") return true;
    if (c === "{" && containsCommaQuantifier(body, i)) return true;
    i++;
  }
  return false;
}

function containsTopLevelAlternation(body: string): boolean {
  let i = 0;
  const n = body.length;
  let depth = 0;
  while (i < n) {
    const c = body[i];
    if (c === "\\") {
      i += 2;
      continue;
    }
    if (c === "[") {
      i++;
      while (i < n && body[i] !== "]") {
        if (body[i] === "\\") i += 2;
        else i++;
      }
      i++;
      continue;
    }
    if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (c === "|" && depth === 0) return true;
    i++;
  }
  return false;
}

function containsCommaQuantifier(s: string, idx: number): boolean {
  // s[idx] === '{'; check for `{n,}` or `{n,m}` form.
  let i = idx + 1;
  const n = s.length;
  while (i < n && s[i] !== "}") {
    if (s[i] === ",") return true;
    i++;
  }
  return false;
}

function stripRegexDelimiters(text: string): string | null {
  if (text.length < 2 || text[0] !== "/") return null;
  // Find last `/` that is not part of a character class.
  let i = 1;
  let lastSlash = -1;
  let inClass = false;
  while (i < text.length) {
    const c = text[i];
    if (c === "\\") {
      i += 2;
      continue;
    }
    if (c === "[") inClass = true;
    else if (c === "]") inClass = false;
    else if (c === "/" && !inClass) lastSlash = i;
    i++;
  }
  if (lastSlash < 0) return null;
  return text.slice(1, lastSlash);
}

function sourceHasMitigation(text: string): boolean {
  for (const name of LINEAR_TIME_ENGINE_NAMES) {
    if (text.includes(`${name}(`) || text.includes(`from "${name}"`) || text.includes(`require("${name}")`)) {
      return true;
    }
  }
  for (const tok of LENGTH_BOUND_TOKENS) {
    if (text.includes(tok)) return true;
  }
  return false;
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function locationOf(node: ts.Node, sf: ts.SourceFile, file: string): Location {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return { kind: "source", file, line: line + 1, col: character + 1 };
}

function looksLikeTestFile(source: string): boolean {
  const hasRunner = TEST_FILE_RUNNER_MARKERS.some((m) => source.includes(m));
  const hasSuite =
    TEST_FILE_SUITE_MARKERS.some((m) => source.includes(m)) ||
    source.startsWith("describe(") ||
    source.startsWith("it(") ||
    source.startsWith("test(");
  return hasRunner && hasSuite;
}

function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}
