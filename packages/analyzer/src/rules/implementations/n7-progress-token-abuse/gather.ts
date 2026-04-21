/**
 * N7 — Deterministic fact gathering for progress-token prediction/injection.
 *
 * AST walk: for each variable declaration or assignment whose identifier name
 * contains a progress-token pattern, classify the RHS. If the RHS is
 * user-controlled or predictable AND no crypto generator appears in the
 * enclosing scope, gather a fact.
 */

import ts from "typescript";
import {
  PROGRESS_TOKEN_IDENTIFIERS,
  USER_SOURCE_ROOTS,
  PREDICTABLE_SOURCE_TOKENS,
  CRYPTO_GENERATORS,
} from "./data/progress-vocabulary.js";

export interface SourceLocation {
  readonly kind: "source_code_line";
  readonly line: number;
  readonly column: number;
  readonly snippet: string;
  readonly enclosing_function: string | null;
}

export type TokenSourceKind = "user-input" | "counter-increment" | "timestamp" | "index" | "integer-literal";

export interface ProgressTokenFact {
  readonly location: SourceLocation;
  readonly target_identifier: string;
  readonly rhs_expression: string;
  readonly source_kind: TokenSourceKind;
  readonly crypto_generator_in_scope: boolean;
}

export interface GatheredFacts {
  readonly facts: ProgressTokenFact[];
  readonly parse_succeeded: boolean;
}

function isProgressTokenIdentifier(name: string): boolean {
  const lower = name.toLowerCase();
  for (const key of Object.keys(PROGRESS_TOKEN_IDENTIFIERS)) {
    if (lower === key || lower === key.replace(/_/g, "")) return true;
  }
  return false;
}

/** Extract the leading identifier of an expression text (before first . [ or ( ). */
function leadingIdentifier(text: string): string {
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === "." || c === "[" || c === "(" || c === " " || c === ";") break;
    i++;
  }
  return text.slice(0, i);
}

function classifyRhs(expr: ts.Expression, sf: ts.SourceFile): TokenSourceKind | null {
  const text = expr.getText(sf);

  // User-input root?
  const root = leadingIdentifier(text).toLowerCase();
  if (Object.prototype.hasOwnProperty.call(USER_SOURCE_ROOTS, root)) {
    return "user-input";
  }

  // Counter increment operators / += N / ++x / x++
  if (ts.isPrefixUnaryExpression(expr) && (expr.operator === ts.SyntaxKind.PlusPlusToken || expr.operator === ts.SyntaxKind.MinusMinusToken)) {
    return "counter-increment";
  }
  if (ts.isPostfixUnaryExpression(expr) && (expr.operator === ts.SyntaxKind.PlusPlusToken || expr.operator === ts.SyntaxKind.MinusMinusToken)) {
    return "counter-increment";
  }
  if (ts.isBinaryExpression(expr)) {
    const op = expr.operatorToken.kind;
    if (op === ts.SyntaxKind.PlusEqualsToken || op === ts.SyntaxKind.MinusEqualsToken) return "counter-increment";
    if (op === ts.SyntaxKind.PlusToken || op === ts.SyntaxKind.MinusToken) {
      const r = expr.right.getText(sf);
      const l = expr.left.getText(sf);
      if (/^[0-9]+$/.test(r) || /^[0-9]+$/.test(l)) return "counter-increment";
    }
  }

  // Timestamp
  for (const key of Object.keys(PREDICTABLE_SOURCE_TOKENS)) {
    if (key === "increment_operator" || key === "length_access") continue;
    if (text.includes(key)) {
      if (key === "indexOf") return "index";
      return "timestamp";
    }
  }

  // Integer literal
  if (ts.isNumericLiteral(expr)) return "integer-literal";

  // Identifier referring to a counter-named variable
  if (ts.isIdentifier(expr)) {
    const n = expr.text.toLowerCase();
    if (n === "counter" || n.endsWith("counter")) return "counter-increment";
  }

  return null;
}

function enclosingFunction(node: ts.Node): ts.Node | null {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur) ||
      ts.isMethodDeclaration(cur) ||
      ts.isClassDeclaration(cur)
    )
      return cur;
    cur = cur.parent;
  }
  return null;
}

function cryptoInScope(scopeText: string): boolean {
  for (const key of Object.keys(CRYPTO_GENERATORS)) {
    if (scopeText.includes(key)) return true;
  }
  if (scopeText.includes("randomUUID(")) return true;
  if (scopeText.includes("uuid(")) return true;
  if (scopeText.includes("nanoid(")) return true;
  return false;
}

function makeLocation(node: ts.Node, sf: ts.SourceFile, source: string): SourceLocation {
  const start = node.getStart(sf);
  const pos = sf.getLineAndCharacterOfPosition(start);
  const line = pos.line + 1;
  const column = pos.character + 1;
  const lineText = source.split("\n")[line - 1] ?? "";
  const encl = enclosingFunction(node);
  const enclName =
    encl && ts.isFunctionDeclaration(encl) && encl.name
      ? encl.name.getText(sf)
      : encl && ts.isMethodDeclaration(encl) && encl.name
      ? encl.name.getText(sf)
      : null;
  return {
    kind: "source_code_line",
    line,
    column,
    snippet: lineText.trim().slice(0, 200),
    enclosing_function: enclName,
  };
}

export function gather(source: string): GatheredFacts {
  const facts: ProgressTokenFact[] = [];

  let sf: ts.SourceFile;
  try {
    sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);
  } catch {
    return { facts, parse_succeeded: false };
  }

  const addFact = (node: ts.Node, name: string, rhs: ts.Expression): void => {
    const kind = classifyRhs(rhs, sf);
    if (!kind) return;
    const encl = enclosingFunction(node);
    const scopeText = encl ? encl.getText(sf) : source;
    const cryptoPresent = cryptoInScope(scopeText);
    if (cryptoPresent) return;
    facts.push({
      location: makeLocation(node, sf, source),
      target_identifier: name,
      rhs_expression: rhs.getText(sf).slice(0, 80),
      source_kind: kind,
      crypto_generator_in_scope: cryptoPresent,
    });
  };

  const visit = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const name = node.name.getText(sf);
      if (isProgressTokenIdentifier(name)) addFact(node, name, node.initializer);
    }
    if (ts.isPropertyDeclaration(node) && node.name && node.initializer) {
      const name = node.name.getText(sf);
      if (isProgressTokenIdentifier(name)) addFact(node, name, node.initializer);
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      let leftName: string | null = null;
      if (ts.isPropertyAccessExpression(node.left)) leftName = node.left.name.getText(sf);
      else if (ts.isIdentifier(node.left)) leftName = node.left.text;
      if (leftName && isProgressTokenIdentifier(leftName)) {
        addFact(node, leftName, node.right);
      }
    }
    ts.forEachChild(node, visit);
  };

  ts.forEachChild(sf, visit);
  return { facts, parse_succeeded: true };
}
