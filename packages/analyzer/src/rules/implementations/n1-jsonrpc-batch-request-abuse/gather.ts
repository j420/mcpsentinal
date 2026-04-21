/**
 * N1 — Deterministic fact gathering for JSON-RPC batch abuse.
 *
 * Walks the TypeScript AST and collects two orthogonal fact classes:
 *   (a) "guarded batch iteration" — an if/else branch whose condition is
 *       Array.isArray on a batch-shaped identifier, whose body iterates,
 *       and whose enclosing scope lacks any size-limit vocabulary.
 *   (b) "unguarded batch map/forEach" — a method call on a batch-named
 *       receiver (batch/requests/messages) whose enclosing function
 *       contains no limit vocabulary anywhere.
 *
 * ZERO regex literals, ZERO string arrays > 5. All vocabulary lives in
 * data/batch-vocabulary.ts as typed records. Structural decisions only.
 */

import ts from "typescript";
import {
  BATCH_IDENTIFIERS,
  ITERATION_METHODS,
  LIMIT_VOCABULARY,
  THROTTLE_VOCABULARY,
} from "./data/batch-vocabulary.js";

export interface SourceLocation {
  readonly kind: "source_code_line";
  readonly line: number;
  readonly column: number;
  readonly snippet: string;
  readonly enclosing_function: string | null;
}

export interface BatchFact {
  readonly fact_kind: "guarded-iteration" | "unguarded-batch-iteration";
  readonly location: SourceLocation;
  readonly iteration_method: string;
  readonly receiver_name: string;
  readonly enclosing_function_text: string;
  readonly limit_vocabulary_present: boolean;
  readonly throttle_vocabulary_present: boolean;
}

export interface GatheredFacts {
  readonly facts: BatchFact[];
  readonly parse_succeeded: boolean;
}

/** Identifier-name tokeniser operating on raw expression text from the AST. */
function lowercaseTokens(text: string): Set<string> {
  const out = new Set<string>();
  let current = "";
  for (const ch of text) {
    const isWord = (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || (ch >= "0" && ch <= "9") || ch === "_";
    if (isWord) {
      current += ch;
    } else {
      if (current) out.add(current.toLowerCase());
      current = "";
    }
  }
  if (current) out.add(current.toLowerCase());
  return out;
}

/** Return the name (or null) of a TS identifier/property name node. */
function identifierNameOf(node: ts.Node, sf: ts.SourceFile): string | null {
  if (ts.isIdentifier(node)) return node.getText(sf);
  if (ts.isPropertyAccessExpression(node)) return node.name.getText(sf);
  return null;
}

/** Is `name` a batch-named identifier per BATCH_IDENTIFIERS? */
function isBatchIdentifier(name: string): boolean {
  return Object.prototype.hasOwnProperty.call(BATCH_IDENTIFIERS, name.toLowerCase());
}

/** Is `name` an array-iteration method? */
function isIterationMethod(name: string): boolean {
  return Object.prototype.hasOwnProperty.call(ITERATION_METHODS, name);
}

/** Does a code block's token set contain any limit vocabulary? */
function containsLimitVocabulary(blockText: string): boolean {
  const tokens = lowercaseTokens(blockText);
  // "length_comparison" is checked separately — it's a pattern, not a token.
  // If there's a .length followed by a comparison operator and a digit in the
  // same textual window, treat the vocabulary as present.
  const hasLengthComparison = hasLengthComparisonStructure(blockText);
  if (hasLengthComparison) return true;
  for (const key of Object.keys(LIMIT_VOCABULARY)) {
    if (key === "length_comparison") continue;
    if (tokens.has(key.toLowerCase())) return true;
  }
  return false;
}

/** Does a code block's token set contain any throttle vocabulary? */
function containsThrottleVocabulary(blockText: string): boolean {
  const tokens = lowercaseTokens(blockText);
  for (const key of Object.keys(THROTTLE_VOCABULARY)) {
    if (tokens.has(key.toLowerCase().replace(/_/g, ""))) return true;
    if (tokens.has(key.toLowerCase())) return true;
  }
  return false;
}

/**
 * Detect `.length` followed (allowing whitespace) by <,>,<=,>=,===,!==,==, and
 * then either an identifier or a numeric literal. This is a structural property
 * of the surrounding text — we scan the tokens produced by character iteration,
 * not a regex literal.
 */
function hasLengthComparisonStructure(text: string): boolean {
  const needle = ".length";
  let from = 0;
  while (true) {
    const idx = text.indexOf(needle, from);
    if (idx < 0) return false;
    let cursor = idx + needle.length;
    while (cursor < text.length && (text[cursor] === " " || text[cursor] === "\t" || text[cursor] === "\n")) {
      cursor++;
    }
    const c0 = text[cursor];
    const c1 = text[cursor + 1];
    const c2 = text[cursor + 2];
    const isCompare =
      c0 === "<" ||
      c0 === ">" ||
      (c0 === "=" && c1 === "=") ||
      (c0 === "!" && c1 === "=");
    if (isCompare) {
      // Skip the comparison operator
      let opEnd = cursor + 1;
      if (c1 === "=") opEnd++;
      if ((c0 === "=" || c0 === "!") && c2 === "=") opEnd++;
      while (opEnd < text.length && (text[opEnd] === " " || text[opEnd] === "\t")) opEnd++;
      const rhs = text[opEnd];
      if (rhs && ((rhs >= "0" && rhs <= "9") || (rhs >= "a" && rhs <= "z") || (rhs >= "A" && rhs <= "Z") || rhs === "_")) {
        return true;
      }
    }
    from = idx + 1;
  }
}

/** Walk up the AST to find the nearest enclosing function node. */
function enclosingFunction(node: ts.Node): ts.Node | null {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur) ||
      ts.isMethodDeclaration(cur)
    ) {
      return cur;
    }
    cur = cur.parent;
  }
  return null;
}

function makeLocation(node: ts.Node, sf: ts.SourceFile, snippetSource: string): SourceLocation {
  const start = node.getStart(sf);
  const pos = sf.getLineAndCharacterOfPosition(start);
  const line = pos.line + 1;
  const column = pos.character + 1;
  const lineText = snippetSource.split("\n")[line - 1] ?? "";
  const enclosing = enclosingFunction(node);
  const enclosingName =
    enclosing && ts.isFunctionDeclaration(enclosing) && enclosing.name
      ? enclosing.name.getText(sf)
      : enclosing && ts.isMethodDeclaration(enclosing) && enclosing.name
      ? enclosing.name.getText(sf)
      : null;
  return {
    kind: "source_code_line",
    line,
    column,
    snippet: lineText.trim().slice(0, 200),
    enclosing_function: enclosingName,
  };
}

/** Detect the `Array.isArray(<batch-named>)` guard expression pattern. */
function isArrayIsArrayGuardOnBatch(node: ts.Node, sf: ts.SourceFile): {
  matched: boolean;
  target: string | null;
} {
  if (!ts.isCallExpression(node)) return { matched: false, target: null };
  if (!ts.isPropertyAccessExpression(node.expression)) return { matched: false, target: null };
  const obj = node.expression.expression.getText(sf);
  const method = node.expression.name.getText(sf);
  if (obj !== "Array" || method !== "isArray") return { matched: false, target: null };
  if (node.arguments.length === 0) return { matched: false, target: null };
  const argText = node.arguments[0].getText(sf);
  // Pull the leading identifier of the argument (e.g. `req.body.batch` → `req`).
  const leadingName = argText.split(/[\s.\[\(]/)[0] ?? "";
  if (leadingName && isBatchIdentifier(leadingName)) {
    return { matched: true, target: argText };
  }
  // Also handle direct batch-named identifiers as argument.
  const allTokens = lowercaseTokens(argText);
  for (const token of allTokens) {
    if (isBatchIdentifier(token)) return { matched: true, target: argText };
  }
  return { matched: false, target: null };
}

export function gather(source: string): GatheredFacts {
  const facts: BatchFact[] = [];

  let sf: ts.SourceFile;
  try {
    sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);
  } catch {
    return { facts, parse_succeeded: false };
  }

  const visit = (node: ts.Node): void => {
    // ── Fact class A: guarded batch iteration ────────────────────────────────
    if (ts.isIfStatement(node)) {
      const condVisit = (n: ts.Node): boolean => {
        const { matched } = isArrayIsArrayGuardOnBatch(n, sf);
        if (matched) return true;
        let found = false;
        ts.forEachChild(n, (c) => {
          if (!found) found = condVisit(c);
        });
        return found;
      };
      if (condVisit(node.expression)) {
        const body = node.thenStatement;
        const bodyText = body.getText(sf);
        const iteratesBody = containsIteration(body, sf);
        const enclosingScopeText = (enclosingFunction(node)?.getText(sf) ?? bodyText);
        const hasLimit = containsLimitVocabulary(enclosingScopeText);
        const hasThrottle = containsThrottleVocabulary(enclosingScopeText);
        if (iteratesBody.matched && !hasLimit && !hasThrottle) {
          facts.push({
            fact_kind: "guarded-iteration",
            location: makeLocation(node, sf, source),
            iteration_method: iteratesBody.method,
            receiver_name: iteratesBody.receiverName,
            enclosing_function_text: enclosingScopeText,
            limit_vocabulary_present: hasLimit,
            throttle_vocabulary_present: hasThrottle,
          });
        }
      }
    }

    // ── Fact class B: unguarded batch map/forEach ────────────────────────────
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const receiver = node.expression.expression.getText(sf);
      const method = node.expression.name.getText(sf);
      const receiverTokens = lowercaseTokens(receiver);
      const receiverIsBatchNamed = Array.from(receiverTokens).some((t) => isBatchIdentifier(t));
      if (receiverIsBatchNamed && isIterationMethod(method)) {
        const enclosing = enclosingFunction(node);
        if (enclosing) {
          const enclosingText = enclosing.getText(sf);
          const hasLimit = containsLimitVocabulary(enclosingText);
          const hasThrottle = containsThrottleVocabulary(enclosingText);
          if (!hasLimit && !hasThrottle) {
            facts.push({
              fact_kind: "unguarded-batch-iteration",
              location: makeLocation(node, sf, source),
              iteration_method: method,
              receiver_name: receiver,
              enclosing_function_text: enclosingText,
              limit_vocabulary_present: hasLimit,
              throttle_vocabulary_present: hasThrottle,
            });
          }
        }
      }
    }

    ts.forEachChild(node, visit);
  };

  ts.forEachChild(sf, visit);
  return { facts, parse_succeeded: true };
}

/** Scan a node's subtree for an iteration call and report the first match. */
function containsIteration(
  root: ts.Node,
  sf: ts.SourceFile,
): { matched: boolean; method: string; receiverName: string } {
  let matched = false;
  let method = "";
  let receiverName = "";
  const walk = (n: ts.Node): void => {
    if (matched) return;
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression)) {
      const m = n.expression.name.getText(sf);
      if (isIterationMethod(m)) {
        matched = true;
        method = m;
        receiverName = n.expression.expression.getText(sf);
        return;
      }
    }
    // for..of / for..in / classic for — also iteration
    if (ts.isForOfStatement(n) || ts.isForInStatement(n) || ts.isForStatement(n)) {
      matched = true;
      method = "for-loop";
      receiverName = n.getText(sf).slice(0, 40);
      return;
    }
    ts.forEachChild(n, walk);
  };
  walk(root);
  return { matched, method, receiverName };
}
